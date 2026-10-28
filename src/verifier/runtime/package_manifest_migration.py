"""Migrate Verifier's root declaration without inventing applicability evidence.

Terminology: YAML Ain't Markup Language (YAML).

Terminology: abstract syntax tree (AST); identifier (ID); Secure Hash Algorithm
256-bit (SHA-256).

This installed engine is specific to Verifier's own repository, not a generic
semantic classifier. Its maintainer command previews by default; the separate
package-manifest refresh transaction lets default root numeric polish replay only
already selected policies. Publication requires an external, exclusive backup
and refuses concurrently changed bytes.
Existing namespace decisions remain explicit, including UNKNOWN outcomes.
JavaScript Object Notation (JSON); command-line interface (CLI);
application programming interface (API); central processing unit (CPU);
operating system (OS).
"""

from __future__ import annotations

import argparse
import ast
from concurrent.futures import ProcessPoolExecutor
from copy import deepcopy
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
from typing import Any

from verifier.core.namespace import NamespaceObject
from verifier.domains.contracts import current_object_routes
from verifier.runtime import (
    namespace_consequences,
    namespace_discovery,
    namespace_contracts,
    namespace_manifest,
    package_harness_applicability,
    package_graph_representation,
)
from verifier.runtime import (
    package_manifest,
    package_namespace_review,
    package_original_kind_catalog,
    package_original_review_computation,
    package_original_review_people,
    package_original_review_systems,
    package_review_stage_gaps,
    package_semantic_review_admission,
    package_semantic_review_commands,
    package_semantic_review_core,
    package_semantic_review_hardware_cli,
    package_semantic_review_operations,
    package_semantic_review_package_object,
    package_semantic_review_partitions,
    package_semantic_review_polish,
    package_semantic_review_records,
    package_semantic_review_scripts,
    package_semantic_review_self_polish,
    package_semantic_review_subjects,
    package_semantic_review_verifier,
    package_semantic_ownership,
    self_polish_estate,
    tier_zero_manifest,
    tier_zero_profile,
)
from verifier.runtime.package_instance_evidence import (
    STRUCTURAL,
    _source_semantic_profile as _validated_source_semantic_profile,
)
from verifier.runtime.self_polish_estate import bytes_digest
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


_COMPACT_TRANSPORT_PREFERRED_BYTES = 8 * 1024 * 1024


_PACKAGE_REVIEW_MODULES = (
    package_namespace_review,
    package_semantic_review_records,
    package_semantic_review_operations,
    package_semantic_review_subjects,
    package_semantic_review_verifier,
    package_semantic_review_scripts,
    package_semantic_review_admission,
    package_semantic_review_commands,
    package_semantic_review_hardware_cli,
    package_semantic_review_partitions,
    package_semantic_review_polish,
    package_semantic_review_self_polish,
    package_original_review_people,
    package_original_review_systems,
    package_original_review_computation,
    package_semantic_review_core,
    package_semantic_review_package_object,
)


# Each review family owns its exact feature-near obligation rationale.  The
# public review document deliberately exposes the classification rationale and
# declaration values separately; this table binds the small, source-owned
# sentence used when those two pieces become one manifest obligation binding.
_PACKAGE_REVIEW_OBLIGATION_SUFFIXES = {
    package_namespace_review: (
        " This Tier-0 declaration names the boundary only; mechanism execution "
        "and higher-tier semantic fulfillment remain unestablished."
    ),
    package_semantic_review_records: (
        " This source-bound Tier-0 declaration states the boundary; mechanism "
        "truth and Tier-1-plus fulfillment remain unestablished."
    ),
    package_semantic_review_operations: (
        " This Tier-0 declaration names the reviewed boundary only; mechanism "
        "execution and Tier-1-plus fulfillment remain unestablished."
    ),
    package_semantic_review_subjects: (
        " This Tier-0 declaration names the reviewed boundary only; mechanism "
        "execution and Tier-1-plus fulfillment remain unestablished."
    ),
    package_semantic_review_verifier: (
        " This Tier-0 declaration names the reviewed boundary only; mechanism "
        "execution and Tier-1-plus fulfillment remain unestablished."
    ),
    package_semantic_review_scripts: (
        " This Tier-0 declaration names the reviewed boundary only; execution "
        "and Tier-1-plus fulfillment remain unestablished."
    ),
    package_semantic_review_admission: (
        " This Tier-0 declaration names the exact reviewed boundary only; "
        "mechanism execution and Tier-1-plus fulfillment remain unestablished."
    ),
    package_semantic_review_commands: (
        " This Tier-0 declaration names the reviewed boundary only; mechanism "
        "execution and Tier-1-plus fulfillment remain unestablished."
    ),
    package_semantic_review_hardware_cli: (
        " This Tier-0 declaration names only the exact reviewed source boundary; "
        "execution and Tier-1-plus fulfillment remain unestablished."
    ),
    package_semantic_review_partitions: (
        " This Tier-0 declaration names the reviewed exact-source boundary only; "
        "mechanism execution, semantic truth, and Tier-1-plus fulfillment remain "
        "unestablished."
    ),
    package_semantic_review_polish: (
        " This Tier-0 declaration names the reviewed boundary only; mechanism "
        "execution and Tier-1-plus fulfillment remain unestablished."
    ),
    package_semantic_review_self_polish: (
        " This Tier-0 declaration names the reviewed boundary only; mechanism "
        "execution and Tier-1-plus fulfillment remain unestablished."
    ),
    package_original_review_people: (
        " This exact-source Tier-0 declaration states the boundary; mechanism "
        "truth and Tier-1-plus fulfillment remain unestablished."
    ),
    package_original_review_systems: (
        " This declaration records the reviewed Tier-0 boundary only; mechanism "
        "execution and Tier-1-plus fulfillment remain unestablished."
    ),
    package_original_review_computation: (
        " This exact-source Tier-0 declaration states the boundary; mechanism "
        "truth and Tier-1-plus fulfillment remain unestablished."
    ),
    package_semantic_review_core: (
        " This Tier-0 declaration names the exact reviewed source boundary only; "
        "mechanism execution, declaration truth, and Tier-1-plus fulfillment "
        "remain unestablished."
    ),
    package_semantic_review_package_object: (
        " This Tier-0 declaration names the exact reviewed source boundary only; "
        "execution, declaration truth, generated-byte freshness and Tier-1-plus "
        "fulfillment remain unestablished."
    ),
}


# The installed root immediately predates these exact catalog additions.  This
# is a finite predecessor, not a rule that permits arbitrary missing surfaces.
_PRE_APPLICABILITY_MISSING_OWNED_PATHS = {
    "vstd-package-graph-contract": frozenset(
        {"src/verifier/runtime/package_contract_profiles.py"}
    ),
    "vstd-package-worker-exchange": frozenset(
        {
            "src/verifier/runtime/emulator_control_execution.py",
            "src/verifier/runtime/emulator_control_worker.py",
            "src/verifier/runtime/token_asset_execution.py",
            "src/verifier/runtime/token_asset_worker.py",
        }
    ),
    "vstd-repository-admission-assets": frozenset(
        {"src/verifier/schemas/verifier-package-contract-coverage-2.schema.json"}
    ),
    "vstd-test-namespace-admission-regressions": frozenset(
        {
            "tests/test_applicability_declaration_contract.py",
            "tests/test_package_contract_profiles.py",
            "tests/test_package_manifest_migration_added_execution.py",
            "tests/test_package_semantic_ownership_added_kind_behavioral.py",
            "tests/test_polish0_interface_adversary.py",
        }
    ),
    "vstd-test-polish-regressions": frozenset(
        {
            "tests/test_package_polish_coordinate_commitments.py",
            "tests/test_package_polish_refresh_binding.py",
        }
    ),
    "vstd-test-runtime-execution-regressions": frozenset(
        {
            "tests/test_added_kind_behavioral_mechanisms.py",
            "tests/test_added_kind_instance_evidence.py",
            "tests/test_added_kind_package_route_integration.py",
            "tests/test_package_asset_execution.py",
            "tests/test_package_emulator_control_execution.py",
            "tests/test_package_subject_binding.py",
        }
    ),
}

_PRE_APPLICABILITY_REPRESENTATION_ROLES = {
    "vstd-accelerator-profile-reader": (
        "Read-only projection of installed declared accelerator profiles."
    ),
    "vstd-accelerator-profile-registry": (
        "Finite accelerator profile catalog and lookup representation."
    ),
    "vstd-accessibility-artifact-reader": (
        "Selected accessibility-artifact acquisition and diagnostic explanation "
        "projection."
    ),
    "vstd-added-kind-behavioral-verifier": (
        "Pure source-bound MARKET, ROBOT and FINBOT retained-evidence certificate "
        "construction and independent replay."
    ),
    "vstd-javascript-parser-protocol": (
        "Parent/isolated-worker JavaScript syntax-census request and response "
        "protocol."
    ),
    "vstd-object-obligation-inventory": (
        "Current object-obligation inventory and registration denominator."
    ),
    "vstd-package-manifest-migration-controller": (
        "Verifier-repository-specific manifest preview, semantic-ownership "
        "migration, review retention, and guarded atomic replacement."
    ),
    "vstd-polish-findings-projection": (
        "Diagnostic report acquisition and deterministic retained-finding "
        "comparison."
    ),
    "vstd-systems-parser-protocol": (
        "Parent/isolated-worker Rust and Bash syntax-census request and response "
        "protocol."
    ),
    "vstd-vgsat-native-verifier-adapters": (
        "Exact vendored AlgoTune predicates, import shim, candidate invocation "
        "and bounded observation wrapper."
    ),
    "vstd-vgsat-public-result-records": (
        "Retained public audit, baseline report and fail-closed live-runtime "
        "blocker record."
    ),
    "vstd-workflow-parser-protocol": (
        "Parent/isolated-worker YAML workflow census, reference resolution and "
        "command declaration protocol."
    ),
}


def _is_exact_reviewed_representation_role_transition(
    object_id: str, prior: Any, current: Any
) -> bool:
    """Recognize one closed predecessor-to-current catalog payload transition."""

    prior_role = _PRE_APPLICABILITY_REPRESENTATION_ROLES.get(object_id)
    if prior_role is None:
        return False
    current_roles = [
        spec.representation_role
        for spec in package_semantic_ownership.SEMANTIC_OWNERSHIP_SPECS
        if spec.object_id == object_id
    ]
    return (
        len(current_roles) == 1
        and prior_role != current_roles[0]
        and prior == {"representation_role": prior_role}
        and current == {"representation_role": current_roles[0]}
    )

# One reviewed named object predates its current three-file source grouping.
# This is a finite lifecycle edge, not a generic invitation to retain stale
# payloads: both old fields and the explicit review selection must match.
_PRE_APPLICABILITY_NAMED_METADATA_TRANSITIONS = {
    "vstd-manifest-write": {
        "payload": {
            "representation_role": "src/verifier/runtime/namespace_cli.py"
        },
        "reason": (
            "The implementation at src/verifier/runtime/namespace_cli.py has an "
            "explicit TRANSACTION boundary."
        ),
    }
}


def _select_named_metadata_transition(
    object_id: str,
    row: dict,
    *,
    current_payload: dict,
    current_reason: str,
    refresh_reviewed: bool,
    select_package_namespace_review: bool,
) -> bool:
    """Recognize one exact selected predecessor; reject every near miss."""

    payload = row.get("payload")
    reason = row.get("reason")
    if payload == current_payload:
        if reason != current_reason:
            raise ValueError(
                "PACKAGE_MIGRATION_PREDECESSOR_OBJECT_REASON_DIFFERS:" + object_id
            )
        return False
    transition = _PRE_APPLICABILITY_NAMED_METADATA_TRANSITIONS.get(object_id)
    if transition is None or payload != transition["payload"]:
        raise ValueError(
            "PACKAGE_MIGRATION_PREDECESSOR_PAYLOAD_DIFFERS:" + object_id
        )
    if reason != transition["reason"]:
        raise ValueError(
            "PACKAGE_MIGRATION_PREDECESSOR_OBJECT_REASON_DIFFERS:" + object_id
        )
    if not (refresh_reviewed and select_package_namespace_review):
        raise ValueError(
            "PACKAGE_MIGRATION_PREDECESSOR_PAYLOAD_DIFFERS:" + object_id
        )
    return True

# These hashes bind status, rationale, declaration text, and evidence paths but
# intentionally exclude evidence SHA-256 values.  The explicit reviewed refresh
# may rebind SHA values only after this exact predecessor projection is proven.
_PRE_APPLICABILITY_CLASSIFICATION_PROJECTIONS = {
    "vstd-package-graph-contract": "sha256:384102ecc9c30f18c95fb0e4aae15696840de718a38c37b5e28fb08415d85345",
    "vstd-package-worker-exchange": "sha256:46e5db24cd3777c053ce7b59296c1d990273ab8c93ea644814071b7513ebd949",
    "vstd-repository-admission-assets": "sha256:59c258808bc0e471f3808887145ac100a35014414de26aae3c1cbe5275290c5e",
    "vstd-test-namespace-admission-regressions": "sha256:f513e8794caba2efb41bc077d7481f9bdc9df67c78d75607310464c668f48883",
    "vstd-test-polish-regressions": "sha256:53ff3b9408a881212384943c9c756745be69073dbc5eacd5e2f071a3d7068ba6",
    "vstd-test-runtime-execution-regressions": "sha256:d5d285f4690f8e0a12edbf08823c9729f8d674c1f5d1f10e30b9dccb4ec8f71c",
}

_PRE_APPLICABILITY_OBLIGATION_PROJECTIONS = {
    "vstd-package-graph-contract": "sha256:40b599e44ffcef00f6c9f1e0326935a21a1c8ef1f7f91c5f6bbf78d9411c198b",
    "vstd-package-worker-exchange": "sha256:00d989827973cc7d5b559ee24686e6a375010bb90f4a4540a61d748ec614e2a0",
    "vstd-repository-admission-assets": "sha256:17faa7c306181fe09b1e56df85d0b1d1f26b0ec4b6d15c9598c6cc361052a068",
    "vstd-test-namespace-admission-regressions": "sha256:fc26298b2944bcfbed51312a949def09ed8dcc65ddeb879511694bb54a096d7f",
    "vstd-test-polish-regressions": "sha256:394aedefe1166badf2abe571de372c3dee83cd2a4473deaf41c300f5ae0c7f62",
    "vstd-test-runtime-execution-regressions": "sha256:a52a56a47c42bfef1d8bff3a32b3bb12fcd1c01fd105aa0ec72d07363ce34266",
}


# One maintainer-reviewed HARNESS transition is installed: the prior root
# denominator, the frozen source catalog, current direct-launch discovery, and
# the resulting rebound denominator.  Every component is exact so this cannot
# turn an arbitrary source or review change into an automatic refresh.
_PACKAGE_HARNESS_REVIEW_TRANSITION = {
    "prior": "sha256:b2141e22938d2f98357cc33e3c1d3106bd44987ce903d91a920b90e1bf3db4c4",
    "catalog": "sha256:62a2db6792188715cb44beefce1945f7a2a773069b3b186c381e03982619ce71",
    "observed": "sha256:fb524c3c0f598d15cfc087959e42e5d428ab462898679514da4cb6467fc149fb",
    "refreshed": "sha256:3e16e79c7b296e9d0c1e14e6eda4550c356e58a18cc6059862d2aa1409fff147",
}

# The bounded workflow worker replaced subprocess.run with subprocess.Popen so
# it can stop a child while output is still over capacity.  That changes a
# launch identity and call digest, not merely a source location.  The normal
# refresh path must therefore reject it.  This one maintainer-reviewed advance
# binds the selected predecessor, reviewed catalog, live discovery and exact
# result independently; the CLI still requires select+refresh+advance.
_PACKAGE_HARNESS_IDENTITY_TRANSITION = {
    "prior": "sha256:3e16e79c7b296e9d0c1e14e6eda4550c356e58a18cc6059862d2aa1409fff147",
    "catalog": "sha256:d4d5b5cc0f50a31c68046c333c41e9b7aea9dbbbb97b65a1d534e1f1c5879e72",
    "observed": "sha256:8505de5c123ef9d3ceb9c035a2bd80a5a546453aa5b5e7bd4d33f27894a780d7",
    "refreshed": "sha256:f1b87307f4fc6a379d77f9e50c370607c0a2c5694bde7abc19876824876f5900",
}
_PACKAGE_HARNESS_IDENTITY_REPLACEMENT = {
    "prior": (
        "src/verifier/runtime/namespace_workflows.py|"
        "scope=<module>.<locals>._run|callee=subprocess.run|ordinal=1"
    ),
    "current": (
        "src/verifier/runtime/namespace_workflows.py|"
        "scope=<module>.<locals>._run|callee=subprocess.Popen|ordinal=1"
    ),
}


# The reviewed 32 -> 40 HARNESS denominator advance is one closed transition.
# The predecessor is the admitted 32-row denominator, the successor is the
# frozen 40-row catalog, and the observed denominator is live discovery.  The
# tenth added launch is the MODEL corrigibility isolated worker (reviewed
# 2026-10-16; see the catalog comment in package_harness_applicability).  Each
# removed, added, call-changed, annotation-changed, or source-only launch is
# pinned by the digest of its reviewed projection.  Source-only drift is bounded
# to rows whose call and annotation are unchanged; refresh rebinds their bytes.
_PACKAGE_HARNESS_SCOPE_TRANSITION = {
    "prior": "sha256:f1b87307f4fc6a379d77f9e50c370607c0a2c5694bde7abc19876824876f5900",
    "catalog": "sha256:4e2ae1e4c30455eaecb8b56215db9467e0e544101ec3f540ac7f4a2bf7216af2",
    "observed": "sha256:10a7ab33711a0fe715799be59e79c9a8cc16b41193398e5b12c24107a72e549e",
    "refreshed": "sha256:4e2ae1e4c30455eaecb8b56215db9467e0e544101ec3f540ac7f4a2bf7216af2",
    "removed": {
        "src/verifier/core/run.py|scope=<module>.<locals>.capture_run|callee=subprocess.run|ordinal=1": "sha256:3478f3107f282cef94d395df4e2a7a1922c4c8c5ecb6e368468cb132d09b706c",
        "src/verifier/runtime/package_execution.py|scope=<module>.<locals>.execute_bound|callee=subprocess.run|ordinal=1": "sha256:7e55502c5603d834eacd91bcd0e8fc2fadd2efb125dbe225648ba5a2a0acf842",
    },
    "added": {
        "src/verifier/domains/contracts/model_corrigibility.py|scope=<module>.<locals>._invoke_worker|callee=subprocess.run|ordinal=1": "sha256:ae932c63e674adc2510f381ad5190ea51f4c35fe93a3236cb4fe866ce498a77e",
        "extensions/languages/src/vstd_languages/__init__.py::WORKER|scope=<module>|callee=subprocess.run|ordinal=3": "sha256:6bc266601b9acf7cbce4bc19e3b88cf08382bb38e8bd913a5fc9417b5514353f",
        "extensions/languages/src/vstd_languages/__init__.py::WORKER|scope=<module>|callee=subprocess.run|ordinal=4": "sha256:8ec186cf11a33eaef3ec51c4a7527daee36da09dfe43845d10ae37f40ddc026b",
        "extensions/languages/src/vstd_languages/__init__.py::WORKER|scope=<module>|callee=subprocess.run|ordinal=5": "sha256:42b7f366228ce9c3770ba718159d88f6ceb9ba6313994e79709e34b100e03052",
        "extensions/languages/src/vstd_languages/__init__.py::WORKER|scope=<module>|callee=subprocess.run|ordinal=6": "sha256:9a91dba58e3281ae8653701bfa89f21bd76b8f6a123a4b911840f8719e12c560",
        "src/verifier/core/owned_process.py|scope=<module>.<locals>.PosixOwnedTree.<locals>.launch|callee=subprocess.Popen|ordinal=1": "sha256:97a81aeaba57c680ffbba637a0090690462703428782dd1d6acb5c156131e3b3",
        "src/verifier/runtime/added_kind_behavioral_routes.py|scope=<module>.<locals>.retained_policy_observations|callee=subprocess.run|ordinal=1": "sha256:fd3232cc3260594be8eb50cd2b94a172efba5f75624ebd392b9b6bafe78f00e1",
        "src/verifier/runtime/package_execution.py|scope=<module>.<locals>._run_package_worker|callee=subprocess.run|ordinal=1": "sha256:bfc3dfe2a4d59a8051ca8de00d7dbf4168739ffcda8cdbc480e18175da3f228a",
        "src/verifier/runtime/policy_enforcement_execution.py|scope=<module>.<locals>._repository_state|callee=subprocess.run|ordinal=1": "sha256:de3a8174f08563e06ef931bb752eddb42df66fc2716a5b9065260e121178771c",
        "src/verifier/runtime/policy_enforcement_routes.py|scope=<module>.<locals>.evaluate_routes|callee=subprocess.run|ordinal=1": "sha256:c104b1102402a99fac46785ea8d2459ce1baab2a2e8b4c6ff3381cf0ad41cc1f",
    },
    "call_changed": {
        "extensions/languages/src/vstd_languages/__init__.py::WORKER|scope=<module>|callee=subprocess.run|ordinal=2": "sha256:af71ae745a3010fcdefc004d018acd4933af392bd64fc7b96c5ded560555b6cd",
        "src/verifier/hardware/adapters/amd.py|scope=<module>.<locals>.AmdAdapter.<locals>.discover|callee=subprocess.run|ordinal=1": "sha256:cb073a9ca847525b1cf0c22dc3d75183c2660719ec3f72667c548a6e88e8473f",
        "src/verifier/hardware/adapters/nvidia.py|scope=<module>.<locals>.NvidiaAdapter.<locals>.discover|callee=subprocess.run|ordinal=1": "sha256:ff1739d0f385d1a117ce28ecd71d5ade19560d8a5c040d2868d846ce33107b6b",
        "src/verifier/runtime/self_polish_estate.py|scope=<module>.<locals>._run_git|callee=subprocess.run|ordinal=1": "sha256:3e127580129887c75b95fbc41557cd0710f1e60fa3e294890ffb4fbe5244eb98",
    },
    "annotation_changed": {
        "extensions/languages/src/vstd_languages/__init__.py::WORKER|scope=<module>|callee=subprocess.run|ordinal=1": "sha256:187ef6e614961ef80b9b42921f2beccd58bce5637f3ef69a270e73d4eddb820c",
    },
    "source_only": {
        "src/verifier/domains/contracts/sim_resource_fresh.py|scope=<module>.<locals>._run|callee=subprocess.run|ordinal=1": "sha256:db0850024737ac46673082b0724e6e08697ac8db22e0e072ddbe5b34187e8a4e",
        "src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>._run_bounded_reconciler|callee=subprocess.Popen|ordinal=1": "sha256:e90dc3fb2279cbad60275361e0ad920457198f3e828391efbf682afa3b33ce06",
        "src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>._source_revision|callee=subprocess.run|ordinal=1": "sha256:51a4dab4c5c3fef96b585fd0234e2fce48ac6074ad7c724b2f178e1b4d94344b",
        "src/verifier/runtime/tier_zero.py|scope=<module>.<locals>._node_structural_reconciliation|callee=subprocess.run|ordinal=1": "sha256:afa546b95d121ab730fc3c21798663ac95e7f6ba6bdcca7c8a8a4655fedc919d",
        "src/verifier/runtime/worker_protocol_worker.py|scope=<module>.<locals>.observe.<locals>.capture|callee=subprocess.run|ordinal=1": "sha256:c35ce69ab1e97e456b8806e17dfa0489cc07468f3cd705d9a4579d2f4ce42b93",
    },
}

# The current closed transition advances the admitted 40-row denominator to
# the 45 reviewed launches that include Tier-zero reasoning.  The old 32 -> 40
# specification above remains available to validate historical receipts; it is
# not generalized into permission for an arbitrary launch-set change.
_PACKAGE_HARNESS_REASONING_SCOPE_TRANSITION = {
    "prior": "sha256:e052c489204bf14647da1175a10d76ee8d75ffb22558375dec44c9d81f758e9b",
    "catalog": "sha256:0a7c579ca3f651f3496873515e57b1a21ee769178e3e3909bd95b96c2b04d714",
    "observed": "sha256:552dc3cb906694bf37af156917ebf05af750d086e0308ef1f3a315e63550c0ce",
    "refreshed": "sha256:0a7c579ca3f651f3496873515e57b1a21ee769178e3e3909bd95b96c2b04d714",
    "removed": {},
    "added": {
        "src/verifier/runtime/tier_zero_reasoning/conditional_dispatch.py|scope=<module>.<locals>._git_python_files|callee=subprocess.run|ordinal=1": "sha256:b2751adc4e5510f874eec35e2a9c2f6b21074eb957a55d3a40fa5b6c33aeffaa",
        "src/verifier/runtime/tier_zero_reasoning/integration.py|scope=<module>.<locals>._git|callee=subprocess.run|ordinal=1": "sha256:e84c8930cb35b5b43aba1203367928ddf710d4e2d90fea01832168cc73d47076",
        "src/verifier/runtime/tier_zero_reasoning/integration.py|scope=<module>.<locals>._step|callee=subprocess.run|ordinal=1": "sha256:7e9ffdceee9cfd7d675011d98820526a8692fadd8a102bc3b82d6c854267d5ce",
        "src/verifier/runtime/tier_zero_reasoning/reasons_check.py|scope=<module>.<locals>.coordinate.<locals>.git|callee=subprocess.run|ordinal=1": "sha256:0bddd71b936eaaf652e600dbc65e4103eeff0e9d72ffa345e431c2361f369574",
        "src/verifier/runtime/tier_zero_reasoning/witness_runner.py|scope=<module>.<locals>.run_one|callee=subprocess.run|ordinal=1": "sha256:cdef245072f5f82526c8bba099137c0958fd2dcb1002434f4a21bf777bd38b98",
    },
    "call_changed": {},
    "annotation_changed": {},
    "source_only": {
        "src/verifier/runtime/self_polish_estate.py|scope=<module>.<locals>._run_git|callee=subprocess.run|ordinal=1": "sha256:42c355ff0a4160d9d900b7a7f226aa4009979e17af6d8c4ca0440c5e82be8e50",
        "src/verifier/runtime/tier_zero.py|scope=<module>.<locals>._node_structural_reconciliation|callee=subprocess.run|ordinal=1": "sha256:afa546b95d121ab730fc3c21798663ac95e7f6ba6bdcca7c8a8a4655fedc919d",
    },
}

# The one-root-reason change makes obligation claims exact, checked and
# load-bearing, and changes the integrated reconciliation from broad role
# coverage to one REQUIRED reason per compiled object/coordinate obligation.
# The three existing process launches did not change identity, call AST or
# reviewed runtime gaps; their enclosing source ASTs and bytes did.  Bind that
# exact successor instead of treating arbitrary future source drift as review.
_PACKAGE_HARNESS_REASON_OBLIGATION_TRANSITION = {
    "prior": "sha256:0a7c579ca3f651f3496873515e57b1a21ee769178e3e3909bd95b96c2b04d714",
    "catalog": "sha256:6208b18e3249f90f745afdf98d51a9943a427b2f7178fd4e90fb22d793507869",
    "observed": "sha256:9899ba47e087133537ecbfc6807868505e497029caf5e94549799f76614c1265",
    "refreshed": "sha256:6208b18e3249f90f745afdf98d51a9943a427b2f7178fd4e90fb22d793507869",
    "removed": {},
    "added": {},
    "call_changed": {},
    "annotation_changed": {},
    "source_only": {
        "src/verifier/runtime/tier_zero_reasoning/integration.py|scope=<module>.<locals>._git|callee=subprocess.run|ordinal=1": "sha256:e84c8930cb35b5b43aba1203367928ddf710d4e2d90fea01832168cc73d47076",
        "src/verifier/runtime/tier_zero_reasoning/integration.py|scope=<module>.<locals>._step|callee=subprocess.run|ordinal=1": "sha256:7e9ffdceee9cfd7d675011d98820526a8692fadd8a102bc3b82d6c854267d5ce",
        "src/verifier/runtime/tier_zero_reasoning/reasons_check.py|scope=<module>.<locals>.coordinate.<locals>.git|callee=subprocess.run|ordinal=1": "sha256:0bddd71b936eaaf652e600dbc65e4103eeff0e9d72ffa345e431c2361f369574",
    },
}

# Three reviewed source-only changes followed the one-root-reason transition:
# package execution replaced a dynamic obligation setattr with the equivalent
# explicit attribute assignment, the policy route fixture replaced a generic
# monkeypatch helper with enumerated engine seams, and the integrated reason
# checker gained the remaining Tier-zero obligations.  Their launch identities,
# call ASTs, necessity reasons, dispositions and unobserved gaps are unchanged.
# Bind this exact predecessor, catalog and live discovery instead of allowing a
# general whole-source AST refresh.
_PACKAGE_HARNESS_SOURCE_AST_REFRESH_TRANSITION = {
    "prior": "sha256:6208b18e3249f90f745afdf98d51a9943a427b2f7178fd4e90fb22d793507869",
    "catalog": "sha256:a8f35094ebd4ce9a5f4dec6172fafcce3876b0ce458342c8d5ac78ad72bd8640",
    "observed": "sha256:c79b0e8d3d73ba5557eda812f4cbb4c0c171bdf1c1fa155882a5802dff7f424d",
    "refreshed": "sha256:a8f35094ebd4ce9a5f4dec6172fafcce3876b0ce458342c8d5ac78ad72bd8640",
    "removed": {},
    "added": {},
    "call_changed": {},
    "annotation_changed": {},
    "source_only": {
        "src/verifier/runtime/package_execution.py|scope=<module>.<locals>._run_package_worker|callee=subprocess.run|ordinal=1": "sha256:bfc3dfe2a4d59a8051ca8de00d7dbf4168739ffcda8cdbc480e18175da3f228a",
        "src/verifier/runtime/policy_enforcement_routes.py|scope=<module>.<locals>.evaluate_routes|callee=subprocess.run|ordinal=1": "sha256:c104b1102402a99fac46785ea8d2459ce1baab2a2e8b4c6ff3381cf0ad41cc1f",
        "src/verifier/runtime/tier_zero_reasoning/reasons_check.py|scope=<module>.<locals>.coordinate.<locals>.git|callee=subprocess.run|ordinal=1": "sha256:0bddd71b936eaaf652e600dbc65e4103eeff0e9d72ffa345e431c2361f369574",
    },
}

# Documented applicability now carries the sole authored reasons.vstd decisions
# into both Python and Node reconciliation and binds their exact digest into the
# admission receipt.  The four direct launches in the two enclosing sources keep
# the same identities, call ASTs, necessity reasons, dispositions and unobserved
# gaps.  This closed transition reviews only their exact source-wide AST and byte
# successors; it does not permit a future source-only refresh by analogy.
_PACKAGE_HARNESS_DOCUMENTED_APPLICABILITY_TRANSITION = {
    "prior": "sha256:a8f35094ebd4ce9a5f4dec6172fafcce3876b0ce458342c8d5ac78ad72bd8640",
    "catalog": "sha256:48bbe1eaa407b3db0f48b4cd42c2a3e52af419ab37828979bd2dd99967241453",
    "observed": "sha256:b1191f34fc560d9ac4cabf255958263018e1a042fbe70a0459a430681d63bd72",
    "refreshed": "sha256:48bbe1eaa407b3db0f48b4cd42c2a3e52af419ab37828979bd2dd99967241453",
    "removed": {},
    "added": {},
    "call_changed": {},
    "annotation_changed": {},
    "source_only": {
        "src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>._run_bounded_reconciler|callee=subprocess.Popen|ordinal=1": "sha256:e90dc3fb2279cbad60275361e0ad920457198f3e828391efbf682afa3b33ce06",
        "src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>._source_revision|callee=subprocess.run|ordinal=1": "sha256:51a4dab4c5c3fef96b585fd0234e2fce48ac6074ad7c724b2f178e1b4d94344b",
        "src/verifier/runtime/tier_zero_reasoning/integration.py|scope=<module>.<locals>._git|callee=subprocess.run|ordinal=1": "sha256:e84c8930cb35b5b43aba1203367928ddf710d4e2d90fea01832168cc73d47076",
        "src/verifier/runtime/tier_zero_reasoning/integration.py|scope=<module>.<locals>._step|callee=subprocess.run|ordinal=1": "sha256:7e9ffdceee9cfd7d675011d98820526a8692fadd8a102bc3b82d6c854267d5ce",
    },
}

# A documented APPLIES reason may now retain obligations when a compiled
# DOES_NOT_APPLY cell lacks established non-applicability evidence.  This changes
# only the enclosing source ASTs and byte/line bindings for Tier-zero closure,
# reason selection (two launches), and the reason checker.  The four launch
# identities, call ASTs, necessity annotations, dispositions, and unobserved gaps
# are unchanged.  Bind this exact successor; future source drift remains outside
# the transition.
_PACKAGE_HARNESS_CONSERVATIVE_APPLIES_TRANSITION = {
    "prior": "sha256:48bbe1eaa407b3db0f48b4cd42c2a3e52af419ab37828979bd2dd99967241453",
    "catalog": "sha256:417c0bfa009a105c80e67ca27df18c8032fa02e25119b9c7ce5724c32fcbeb43",
    "observed": "sha256:29d55c5358303d6a6c84bcf101f3d97314bac0ce054fa8439f279ca1eed54b2e",
    "refreshed": "sha256:417c0bfa009a105c80e67ca27df18c8032fa02e25119b9c7ce5724c32fcbeb43",
    "removed": {},
    "added": {},
    "call_changed": {},
    "annotation_changed": {},
    "source_only": {
        "src/verifier/runtime/tier_zero.py|scope=<module>.<locals>._node_structural_reconciliation|callee=subprocess.run|ordinal=1": "sha256:afa546b95d121ab730fc3c21798663ac95e7f6ba6bdcca7c8a8a4655fedc919d",
        "src/verifier/runtime/tier_zero_reasoning/integration.py|scope=<module>.<locals>._git|callee=subprocess.run|ordinal=1": "sha256:e84c8930cb35b5b43aba1203367928ddf710d4e2d90fea01832168cc73d47076",
        "src/verifier/runtime/tier_zero_reasoning/integration.py|scope=<module>.<locals>._step|callee=subprocess.run|ordinal=1": "sha256:7e9ffdceee9cfd7d675011d98820526a8692fadd8a102bc3b82d6c854267d5ce",
        "src/verifier/runtime/tier_zero_reasoning/reasons_check.py|scope=<module>.<locals>.coordinate.<locals>.git|callee=subprocess.run|ordinal=1": "sha256:0bddd71b936eaaf652e600dbc65e4103eeff0e9d72ffa345e431c2361f369574",
    },
}

# Namespace classification now emits the same complete obligation and decision
# graph in a lossless normalized representation: exact obligation contracts are
# shared once, and deterministic profile constants remain explicitly
# reconstructable.  The two existing namespace-admission launches keep their
# identities, call ASTs, necessity annotations, dispositions, and gaps.  Only
# their enclosing source bytes/AST advance, so this transition authorizes that
# exact two-row successor and no general source refresh.
_PACKAGE_HARNESS_NORMALIZED_OUTPUT_TRANSITION = {
    "prior": "sha256:417c0bfa009a105c80e67ca27df18c8032fa02e25119b9c7ce5724c32fcbeb43",
    "catalog": "sha256:158951050ab27c2f2fee975bc3b85c8c7bc1592f100659e764f44980ecfa0a6b",
    "observed": "sha256:067d1bfaec6089f6388d77acfb4564321c6d1456d9a5c5ba66bb4e2f280255e4",
    "refreshed": "sha256:158951050ab27c2f2fee975bc3b85c8c7bc1592f100659e764f44980ecfa0a6b",
    "removed": {},
    "added": {},
    "call_changed": {},
    "annotation_changed": {},
    "source_only": {
        "src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>._run_bounded_reconciler|callee=subprocess.Popen|ordinal=1": "sha256:e90dc3fb2279cbad60275361e0ad920457198f3e828391efbf682afa3b33ce06",
        "src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>._source_revision|callee=subprocess.run|ordinal=1": "sha256:51a4dab4c5c3fef96b585fd0234e2fce48ac6074ad7c724b2f178e1b4d94344b",
    },
}

# The consequence compiler now supplies the independent Node reconciler with
# the exact catalog/compiler decisions that distinguish native structural roles
# from nonstructural retained APPLIES roles.  The sole authored decisions remain
# in reasons.vstd; this changes only the two namespace-admission source-wide AST,
# byte, and line bindings.  Launch identities, call ASTs, review annotations,
# dispositions, and explicit gaps are unchanged.  Pin the exact predecessor,
# frozen successor, and live discovery so later source drift still fails closed.
_PACKAGE_HARNESS_CONSEQUENCE_PARITY_TRANSITION = {
    "prior": "sha256:158951050ab27c2f2fee975bc3b85c8c7bc1592f100659e764f44980ecfa0a6b",
    "catalog": "sha256:51aa2b7320dd56096c0af67a745a628b9951ab8431ee6f8f02d80ea24006e062",
    "observed": "sha256:16ba0fc5bc1999c62e75bed15f7b97573c962a36cb197ebe565f31cebae2c913",
    "refreshed": "sha256:51aa2b7320dd56096c0af67a745a628b9951ab8431ee6f8f02d80ea24006e062",
    "removed": {},
    "added": {},
    "call_changed": {},
    "annotation_changed": {},
    "source_only": {
        "src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>._run_bounded_reconciler|callee=subprocess.Popen|ordinal=1": "sha256:e90dc3fb2279cbad60275361e0ad920457198f3e828391efbf682afa3b33ce06",
        "src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>._source_revision|callee=subprocess.run|ordinal=1": "sha256:51a4dab4c5c3fef96b585fd0234e2fce48ac6074ad7c724b2f178e1b4d94344b",
    },
}

# Tier-zero exposed-surface closure now consumes the already installed native
# applicability verifier for the three exact repository-boundary sentinels.
# The independent Node reconciliation launch itself is unchanged: its identity,
# call AST, necessity annotation, disposition, and explicit gaps are identical.
# Only the enclosing tier_zero.py source-wide AST, bytes, and line coordinate
# advance.  Bind that exact predecessor, catalog successor, and live discovery;
# no later source drift is accepted by analogy.
_PACKAGE_HARNESS_TIER_ZERO_BOUNDARY_TRANSITION = {
    "prior": "sha256:51aa2b7320dd56096c0af67a745a628b9951ab8431ee6f8f02d80ea24006e062",
    "catalog": "sha256:0d8cf9f72cb3a65f8b8578caa107da5e14c40e78d7e67bb5279f484b38578877",
    "observed": "sha256:d85b73073b06f873a56ecc0c307a5d8aa76d6ed97581320ee99d5b70a05580e9",
    "refreshed": "sha256:0d8cf9f72cb3a65f8b8578caa107da5e14c40e78d7e67bb5279f484b38578877",
    "removed": {},
    "added": {},
    "call_changed": {},
    "annotation_changed": {},
    "source_only": {
        "src/verifier/runtime/tier_zero.py|scope=<module>.<locals>._node_structural_reconciliation|callee=subprocess.run|ordinal=1": "sha256:afa546b95d121ab730fc3c21798663ac95e7f6ba6bdcca7c8a8a4655fedc919d",
    },
}

# Tier zero now composes checked reasons.vstd applicability answers with the
# source catalog so they retain obligations without becoming source-role
# claims.  The Node reconciliation launch is untouched: identity, call AST,
# annotation, disposition, gaps, and line coordinate are identical.  Only the
# enclosing tier_zero.py source bytes and source-wide AST advance.
_PACKAGE_HARNESS_TIER_ZERO_REASON_RETENTION_TRANSITION = {
    "prior": "sha256:0d8cf9f72cb3a65f8b8578caa107da5e14c40e78d7e67bb5279f484b38578877",
    "catalog": "sha256:d939b2569f8448f7fd3eda24f0448b0d0e41bb7bef8ed2eb179b42d368a25268",
    "observed": "sha256:1810dfa127ace3f2cfb2ed4f1440944dc1c607cfc7506b4517a5469d992d7f92",
    "refreshed": "sha256:d939b2569f8448f7fd3eda24f0448b0d0e41bb7bef8ed2eb179b42d368a25268",
    "removed": {},
    "added": {},
    "call_changed": {},
    "annotation_changed": {},
    "source_only": {
        "src/verifier/runtime/tier_zero.py|scope=<module>.<locals>._node_structural_reconciliation|callee=subprocess.run|ordinal=1": "sha256:afa546b95d121ab730fc3c21798663ac95e7f6ba6bdcca7c8a8a4655fedc919d",
    },
}

# Tier zero now narrows checked applicability answers to the original 25-kind
# denominator before handing them to the source catalog.  The Node launch is
# still identical in identity, call AST, annotation, disposition, gaps, and
# line coordinate; only its enclosing source bytes and source-wide AST move.
_PACKAGE_HARNESS_TIER_ZERO_RETENTION_DENOMINATOR_TRANSITION = {
    "prior": "sha256:d939b2569f8448f7fd3eda24f0448b0d0e41bb7bef8ed2eb179b42d368a25268",
    "catalog": "sha256:29ec4aac8238abd1ebfe02a9f771ea91d99ddb24cf303e560e3479c1a4e186d7",
    "observed": "sha256:07dcd3994e0c99bb4575429c023ad56668ccd7cb9075820f9db2311888636c23",
    "refreshed": "sha256:29ec4aac8238abd1ebfe02a9f771ea91d99ddb24cf303e560e3479c1a4e186d7",
    "removed": {},
    "added": {},
    "call_changed": {},
    "annotation_changed": {},
    "source_only": {
        "src/verifier/runtime/tier_zero.py|scope=<module>.<locals>._node_structural_reconciliation|callee=subprocess.run|ordinal=1": "sha256:afa546b95d121ab730fc3c21798663ac95e7f6ba6bdcca7c8a8a4655fedc919d",
    },
}

# Package-graph reconciliation already admits a four-times larger bounded wire
# and output envelope than the standard profile.  Its deadline now scales by
# the same finite factor so the independent Node reader can complete on the
# admitted package graph under load.  Both direct-launch calls are unchanged in
# identity, call AST, necessity annotation, disposition, and explicit gaps;
# only namespace_admission.py source bytes, source-wide AST, and line positions
# advance.  This transition accepts only that exact predecessor and successor.
_PACKAGE_HARNESS_NAMESPACE_RECONCILIATION_TIMEOUT_TRANSITION = {
    "prior": "sha256:29ec4aac8238abd1ebfe02a9f771ea91d99ddb24cf303e560e3479c1a4e186d7",
    "catalog": "sha256:4d766822cb5d034c4925200e9ba8cd385c9768eeaf02c2396c43dc6407753c65",
    "observed": "sha256:155ee97031546d25b220f275824c6ccb0f635edd0ad214b369db4b7d9d0da596",
    "refreshed": "sha256:4d766822cb5d034c4925200e9ba8cd385c9768eeaf02c2396c43dc6407753c65",
    "removed": {},
    "added": {},
    "call_changed": {},
    "annotation_changed": {},
    "source_only": {
        "src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>._run_bounded_reconciler|callee=subprocess.Popen|ordinal=1": "sha256:e90dc3fb2279cbad60275361e0ad920457198f3e828391efbf682afa3b33ce06",
        "src/verifier/runtime/namespace_admission.py|scope=<module>.<locals>._source_revision|callee=subprocess.run|ordinal=1": "sha256:51a4dab4c5c3fef96b585fd0234e2fce48ac6074ad7c724b2f178e1b4d94344b",
    },
}

# The sole authored reason ledger now contains the complete Tier-one package
# denominator. Raising its finite selector capacity changes only the enclosing
# source bytes and canonical AST for the two existing integration launches; the
# launch identities, call ASTs, reviewed reasons, and unobserved gaps are fixed.
_PACKAGE_HARNESS_ROOT_REASON_CAPACITY_TRANSITION = {
    "prior": "sha256:4d766822cb5d034c4925200e9ba8cd385c9768eeaf02c2396c43dc6407753c65",
    "catalog": "sha256:9f4e25c99ea1586e32d5451438e75f00f91ad61311ff9bfdc64db3cc5757af31",
    "observed": "sha256:c9de0473764c27198fa37185566cbf5dfaa084775fda9673bf4a1181bfc22b3b",
    "refreshed": "sha256:9f4e25c99ea1586e32d5451438e75f00f91ad61311ff9bfdc64db3cc5757af31",
    "removed": {},
    "added": {},
    "call_changed": {},
    "annotation_changed": {},
    "source_only": {
        "src/verifier/runtime/tier_zero_reasoning/integration.py|scope=<module>.<locals>._git|callee=subprocess.run|ordinal=1": "sha256:e84c8930cb35b5b43aba1203367928ddf710d4e2d90fea01832168cc73d47076",
        "src/verifier/runtime/tier_zero_reasoning/integration.py|scope=<module>.<locals>._step|callee=subprocess.run|ordinal=1": "sha256:7e9ffdceee9cfd7d675011d98820526a8692fadd8a102bc3b82d6c854267d5ce",
    },
}

# The numeric Tier-2 fresh SIM checker now reports the exact retained negative
# refusal detail after a malformed evidence binding.  Its isolated interpreter
# launch is unchanged in identity, call AST, necessity annotation,
# disposition, and gaps.  Only the enclosing source bytes, canonical AST, and
# line coordinate advance through this exact reviewed transition.
_PACKAGE_HARNESS_FRESH_SIM_REFUSAL_TRANSITION = {
    "prior": "sha256:9f4e25c99ea1586e32d5451438e75f00f91ad61311ff9bfdc64db3cc5757af31",
    "catalog": "sha256:72c5e90c2204fcc5d7b92ca8dee10e722e99b08f491dcd3cf783ff96c927d299",
    "observed": "sha256:c8155a97a9f2f3df8832ebd58dc80679a07a94651a34f0a118dcda7a7581ef78",
    "refreshed": "sha256:72c5e90c2204fcc5d7b92ca8dee10e722e99b08f491dcd3cf783ff96c927d299",
    "removed": {},
    "added": {},
    "call_changed": {},
    "annotation_changed": {},
    "source_only": {
        "src/verifier/domains/contracts/sim_resource_fresh.py|scope=<module>.<locals>._run|callee=subprocess.run|ordinal=1": "sha256:db0850024737ac46673082b0724e6e08697ac8db22e0e072ddbe5b34187e8a4e",
    },
}

# The fixed worker-PROTOCOL specimen contains two sequential 30-second peer
# launches, so its owned outer process now uses the adapter's reviewed
# 90-second compositional ceiling.  The trusted subprocess seam itself is
# unchanged in identity, call AST, review annotation, disposition, and gaps.
# Only package_execution.py source bytes, source-wide AST, and line coordinate
# advance through this exact predecessor/catalog/discovery transition.
_PACKAGE_HARNESS_WORKER_PROTOCOL_TIMEOUT_TRANSITION = {
    "prior": "sha256:72c5e90c2204fcc5d7b92ca8dee10e722e99b08f491dcd3cf783ff96c927d299",
    "catalog": "sha256:cb6da648773214da6dc76fb394198abc38889b0eed835989fa85189b48640fd2",
    "observed": "sha256:78e112e82990042eccbecf7416632f76af05686bd53a29e7cc9c041196a773d4",
    "refreshed": "sha256:cb6da648773214da6dc76fb394198abc38889b0eed835989fa85189b48640fd2",
    "removed": {},
    "added": {},
    "call_changed": {},
    "annotation_changed": {},
    "source_only": {
        "src/verifier/runtime/package_execution.py|scope=<module>.<locals>._run_package_worker|callee=subprocess.run|ordinal=1": "sha256:bfc3dfe2a4d59a8051ca8de00d7dbf4168739ffcda8cdbc480e18175da3f228a",
    },
}

# The manifest worker now counts the actual exclusive-create and replacement
# edges so TRANSACTION-3.3 and TRANSACTION-3.4 can enforce an exact one-attempt
# ceiling.  Its private Git initialization launch is unchanged in identity,
# call AST, reviewed necessity, disposition, gaps, and line coordinate.  Only
# the enclosing worker bytes and source-wide AST advance through this exact
# predecessor/catalog/discovery transition; later source drift still refuses.
_PACKAGE_HARNESS_MANIFEST_RETRY_LIMIT_TRANSITION = {
    "prior": "sha256:cb6da648773214da6dc76fb394198abc38889b0eed835989fa85189b48640fd2",
    "catalog": "sha256:0b78ade9e3fda883da9567732ec8b8903bbf6653c329894563c3e01cdfa78766",
    "observed": "sha256:71edbd97ac7ebcee5573a659dd993ef4e996519f645dbeafcbef1af44b175c2a",
    "refreshed": "sha256:0b78ade9e3fda883da9567732ec8b8903bbf6653c329894563c3e01cdfa78766",
    "removed": {},
    "added": {},
    "call_changed": {},
    "annotation_changed": {},
    "source_only": {
        "src/verifier/runtime/manifest_write_worker.py|scope=<module>.<locals>.observe.<locals>.repository|callee=subprocess.run|ordinal=1": "sha256:c1970d11cb0c3d4966706355259dab1b826d922580b390ee48bad03526b742e0",
    },
}

# PRDEL v2 now admits the package's large exact ledgers under a larger but still
# finite snapshot window.  Its Git wrapper carries the selected output ceiling
# explicitly and rejects values outside the reviewed maximum.  The direct
# subprocess call retains its identity, call AST, necessity annotation,
# disposition, and gaps; only prdel.py bytes, source-wide AST, and line move.
# This closed transition binds that exact predecessor and successor, so no
# later PRDEL source drift can inherit this review by analogy.
_PACKAGE_HARNESS_PRDEL_LARGE_ARTIFACT_TRANSITION = {
    "prior": "sha256:0b78ade9e3fda883da9567732ec8b8903bbf6653c329894563c3e01cdfa78766",
    "catalog": "sha256:de0a6c12eb9926bf62b4756bbd71f9f7402f8e3a26b98ac22388ae4b2aaa313b",
    "observed": "sha256:d586b50d242e67e9444aab127e38655312dbafc90dae78b3b1deb8a1505a774f",
    "refreshed": "sha256:de0a6c12eb9926bf62b4756bbd71f9f7402f8e3a26b98ac22388ae4b2aaa313b",
    "removed": {},
    "added": {},
    "call_changed": {},
    "annotation_changed": {},
    "source_only": {
        "src/verifier/runtime/prdel.py|scope=<module>.<locals>._git|callee=subprocess.run|ordinal=1": "sha256:4558dd1bd17e34bec8a37d82917494ba88d0d24cb02c303730e46275c2a42d1d",
    },
}
# Retaining an authored APPLIES reason after the registry adopts the same
# classification changes tier_zero.py's source-wide AST.  The Node launch call,
# complete launch denominator and review annotations are unchanged.  Bind this
# exact predecessor and reviewed successor rather than accepting general AST drift.
_PACKAGE_HARNESS_ADOPTED_REASON_TRANSITION = {
    "prior": "sha256:3b737c2addce229838959b55184754f5ea32577e3612ad222b5a776ba395be94",
    "catalog": "sha256:9a776b64935f2dc4f734d800b7024745743efa0a514ba0786e959cc9a88ed434",
    "observed": "sha256:054282d3db639ffe68b857dd19f34fa6d2845ec7b96abf354b61b8e72a31810f",
    "refreshed": "sha256:9a776b64935f2dc4f734d800b7024745743efa0a514ba0786e959cc9a88ed434",
    "removed": {},
    "added": {},
    "call_changed": {},
    "annotation_changed": {},
    "source_only": {
        "src/verifier/runtime/tier_zero.py|scope=<module>.<locals>._node_structural_reconciliation|callee=subprocess.run|ordinal=1": "sha256:afa546b95d121ab730fc3c21798663ac95e7f6ba6bdcca7c8a8a4655fedc919d",
    },
}
_PACKAGE_HARNESS_SCOPE_TRANSITIONS = (
    _PACKAGE_HARNESS_SCOPE_TRANSITION,
    _PACKAGE_HARNESS_REASONING_SCOPE_TRANSITION,
    _PACKAGE_HARNESS_REASON_OBLIGATION_TRANSITION,
    _PACKAGE_HARNESS_SOURCE_AST_REFRESH_TRANSITION,
    _PACKAGE_HARNESS_DOCUMENTED_APPLICABILITY_TRANSITION,
    _PACKAGE_HARNESS_CONSERVATIVE_APPLIES_TRANSITION,
    _PACKAGE_HARNESS_NORMALIZED_OUTPUT_TRANSITION,
    _PACKAGE_HARNESS_CONSEQUENCE_PARITY_TRANSITION,
    _PACKAGE_HARNESS_TIER_ZERO_BOUNDARY_TRANSITION,
    _PACKAGE_HARNESS_TIER_ZERO_REASON_RETENTION_TRANSITION,
    _PACKAGE_HARNESS_TIER_ZERO_RETENTION_DENOMINATOR_TRANSITION,
    _PACKAGE_HARNESS_NAMESPACE_RECONCILIATION_TIMEOUT_TRANSITION,
    _PACKAGE_HARNESS_ROOT_REASON_CAPACITY_TRANSITION,
    _PACKAGE_HARNESS_FRESH_SIM_REFUSAL_TRANSITION,
    _PACKAGE_HARNESS_WORKER_PROTOCOL_TIMEOUT_TRANSITION,
    _PACKAGE_HARNESS_MANIFEST_RETRY_LIMIT_TRANSITION,
    _PACKAGE_HARNESS_PRDEL_LARGE_ARTIFACT_TRANSITION,
    _PACKAGE_HARNESS_ADOPTED_REASON_TRANSITION,
)


def _pre_applicability_registry_digest(
    registry: dict[str, namespace_contracts.KindContract],
) -> str:
    """Derive the one installed-registry predecessor this migration accepts.

    Applicability declarations were added to every admission obligation without
    changing the kind, inheritance, obligation, or declaration denominator.
    Projecting only those two new fields reconstructs the exact prior digest;
    accepting a caller-supplied digest or a general mismatch here would let a
    forged registry claim acquire current-contract validation.
    """

    contracts = deepcopy(namespace_contracts.registry_document(registry)["contracts"])
    for contract in contracts:
        for obligation in contract["obligations"]:
            if set(("applicability", "applicability_digest")) - set(obligation):
                raise ValueError(
                    "PACKAGE_MIGRATION_REGISTRY_PREDECESSOR_UNAVAILABLE"
                )
            obligation.pop("applicability")
            obligation.pop("applicability_digest")
    return value_digest(contracts)


def _review_projection(bindings: dict, *, classification: bool) -> dict:
    """Project semantic review bytes while excluding only evidence digests."""

    projected = {}
    for identifier, binding in sorted(bindings.items()):
        record = {
            "reason": binding.get("reason"),
            "evidence_paths": sorted(
                reference.get("path")
                for reference in binding.get("evidence", ())
                if isinstance(reference, dict)
            ),
        }
        if classification:
            record["status"] = binding.get("status")
        else:
            record["declaration"] = binding.get("declaration")
        projected[identifier] = record
    return projected


def _is_original_primary_kind(
    registry: dict[str, namespace_contracts.KindContract], kind: str
) -> bool:
    """Return whether ``kind`` is one of the original non-generic roots.

    Added consequence kinds extend ``OBJECT`` and remain owned by their
    dedicated review catalogs.  An original primary root, by contrast, is an
    explicit fact of the package row itself and therefore requires a current
    evidenced APPLIES answer instead of an indefinitely unresolved question.
    """

    return kind != "OBJECT" and registry[kind].extends is None


def _reviewed_semantic_specializations(
    row: dict,
    previous: dict,
    registry: dict[str, namespace_contracts.KindContract],
) -> list[str]:
    """Install current catalog roles and retain only coherent reviewed additions.

    Semantic ownership is an exact current-source denominator. An older row may
    carry a separately reviewed role beyond that denominator, but the label alone
    is not evidence: retaining it requires an evidenced APPLIES decision and the
    complete obligation-key denominator for that kind. This retires historical
    labels whose review was removed or never materialized without erasing a real
    independently reviewed extension.
    """

    selected = set(row["specializations"])
    classifications = previous.get("classification", {})
    obligations = previous.get("obligations", {})
    for kind in previous.get("specializations", ()):
        if kind in selected or kind not in registry:
            continue
        decision = classifications.get(kind, {})
        required = {
            obligation["id"]
            for obligation in namespace_contracts.requirements_for(registry, (kind,))
        }
        if (
            type(decision) is dict
            and decision.get("status") == "APPLIES"
            and type(decision.get("reason")) is str
            and decision["reason"].strip()
            and type(decision.get("evidence")) is list
            and bool(decision["evidence"])
            and type(obligations) is dict
            and required <= set(obligations)
        ):
            selected.add(kind)
    return sorted(selected)


def _primary_original_kind_reason(kind: str, object_reason: str) -> str:
    """Bind primary-root applicability to the exact source-owned object claim."""

    return (
        "The package object declares "
        + kind
        + " as its primary original namespace kind. Its source-owned object "
        "reason is: "
        + object_reason
        + " This direct role declaration establishes applicability only; it "
        "does not satisfy the kind's obligations or any higher polish tier."
    )


def _evidence_paths(
    evidence: object,
    *,
    expected: set[str],
    files: dict[str, str],
    permit_stale_sha: bool,
    error: str,
) -> None:
    """Require one exact path denominator; only reviewed refresh may rebind SHA."""

    if type(evidence) is not list or any(
        type(reference) is not dict
        or set(reference) != {"path", "sha256"}
        or type(reference["path"]) is not str
        or type(reference["sha256"]) is not str
        for reference in evidence
    ):
        raise ValueError(error)
    paths = [reference["path"] for reference in evidence]
    if len(paths) != len(set(paths)) or set(paths) != expected:
        raise ValueError(error)
    if not permit_stale_sha and any(
        files.get(reference["path"]) != reference["sha256"]
        for reference in evidence
    ):
        raise ValueError(error)


def _validate_current_or_pre_applicability_bridge(
    root: Path,
    document: dict,
    *,
    refresh_reviewed: bool,
    select_package_namespace_review: bool,
    install_semantic_ownership: bool,
) -> None:
    """Validate current v4/v5 input, or one exact installed-registry upgrade.

    The temporary digest substitution grants no manifest content authority. It
    only permits the full ordinary bridge validator to inspect the prior bytes
    under the current canonical installed registry. Custom extensions remain an
    explicit merge, and every object, edge, representation, and selected check
    must still satisfy the normal validator before migration can continue.
    """

    try:
        package_manifest.validate_bridge(document)
        return
    except ValueError as exc:
        if str(exc) != "NAMESPACE_REGISTRY_DIGEST_DIFFERS":
            raise

    declared = document.get("namespace")
    if type(declared) is not dict or declared.get("extensions") != []:
        raise ValueError(
            "PACKAGE_MIGRATION_CUSTOM_EXTENSIONS_REQUIRE_EXPLICIT_MERGE"
        )
    registry = namespace_contracts.namespace_registry()
    if declared.get("registry_digest") != _pre_applicability_registry_digest(
        registry
    ):
        raise ValueError("NAMESPACE_REGISTRY_DIGEST_DIFFERS")

    validation_copy = deepcopy(document)
    validation_copy["namespace"]["registry_digest"] = (
        namespace_contracts.registry_document(registry)["digest"]
    )
    package_manifest.validate_bridge(validation_copy)
    observed = namespace_discovery.discover(root)
    files = {
        row["path"]: row["sha256"]
        for row in observed.get("census", {}).get("files", ())
        if type(row) is dict
        and type(row.get("path")) is str
        and type(row.get("sha256")) is str
    }
    _validate_pre_applicability_namespace_semantics(
        root,
        document,
        registry,
        observed=observed,
        files=files,
        permit_stale_sha=refresh_reviewed,
        select_package_namespace_review=select_package_namespace_review,
        install_semantic_ownership=install_semantic_ownership,
    )


def _validate_pre_applicability_namespace_semantics(
    root: Path,
    document: dict,
    registry: dict[str, namespace_contracts.KindContract],
    *,
    observed: dict,
    files: dict[str, str],
    permit_stale_sha: bool,
    select_package_namespace_review: bool,
    install_semantic_ownership: bool,
) -> None:
    """Reject semantic row drift hidden behind the recognized old digest.

    The ordinary bridge proves typed base composition, but an additive OBJECT
    row can still change its primary refinement, accumulate a consequential
    role, or invent an obligation key without changing that base graph. Build
    the accepted identity surface from the installed retained graph, named
    source groups, semantic ownership catalog, and explicit review catalogs.
    Existing rows may remain unresolved, but a decided status must match the
    source-owned review and every carried role must have that source basis.
    """

    expected: dict[str, dict] = {}
    retained_objects = {
        item.object_id: item
        for item in tier_zero_manifest._namespace_objects(
            tier_zero_manifest.installed_object_declarations()
        )
    }
    for row in tier_zero_manifest.installed_object_declarations():
        expected[row["object_id"]] = {
            "kind": row["object_kind"],
            "specializations": set(),
            "operands": deepcopy(row["edges"]),
            "installed_spec": None,
            "retained_role": row["role"],
            "retained_payload": dict(
                retained_objects[row["object_id"]].payload
            ),
        }

    named: dict[str, dict] = {}
    for path, (object_id, kind, specializations) in _NAMED.items():
        candidate = {
            "kind": kind,
            "specializations": set(specializations),
            "operands": {},
            "installed_spec": None,
            "named_paths": {path},
        }
        prior = named.get(object_id)
        if prior is None:
            named[object_id] = candidate
            continue
        prior_paths = prior["named_paths"]
        candidate_paths = candidate.pop("named_paths")
        prior_shape = {
            key: value for key, value in prior.items() if key != "named_paths"
        }
        if prior_shape != candidate:
            raise ValueError("PACKAGE_MIGRATION_NAMED_CATALOG_CONFLICT")
        prior_paths.update(candidate_paths)
    expected.update(named)

    specs = {
        spec.object_id: spec
        for spec in package_semantic_ownership.SEMANTIC_OWNERSHIP_SPECS
    }
    rows = document["namespace"]["objects"]
    rows_by_id = {row["object_id"]: row for row in rows}
    named_ids = set(named)
    installed_specs: dict[str, object] = {}
    for object_id, spec in specs.items():
        row = rows_by_id.get(object_id)
        installed = object_id not in named_ids and row is not None
        if object_id in named_ids and row is not None:
            installed = (
                row.get("kind") == spec.primary_kind
                and set(spec.specializations)
                <= set(row.get("specializations", ()))
            )
        if not installed:
            continue
        installed_specs[object_id] = spec
        expected[object_id] = {
            "kind": spec.primary_kind,
            "specializations": set(spec.specializations),
            "operands": {role: list(targets) for role, targets in spec.operands},
            "installed_spec": spec,
        }

    by_kind = {
        row["object_kind"]: row["object_id"]
        for row in tier_zero_manifest.installed_object_declarations()
    }
    installed_semantic_owners = _semantic_owner_index(
        tuple(installed_specs.values())
    )
    pending_specs = {
        object_id: spec
        for object_id, spec in specs.items()
        if object_id not in installed_specs
    }
    if install_semantic_ownership:
        validated_specs = {
            spec.object_id: spec
            for spec in package_semantic_ownership.validate_catalog(root)
        }
        if validated_specs != specs:
            raise ValueError(
                "PACKAGE_MIGRATION_PREDECESSOR_SEMANTIC_CATALOG_DIFFERS"
            )
        routing_specs = specs
    else:
        routing_specs = installed_specs
    semantic_owners = _semantic_owner_index(tuple(routing_specs.values()))
    legacy_pending_paths: dict[str, set[str]] = {}
    if install_semantic_ownership:
        for spec in pending_specs.values():
            for path in spec.owned_paths:
                legacy_owner = _owner_for_path(
                    path,
                    by_kind,
                    installed_semantic_owners if installed_specs else None,
                )
                legacy_pending_paths.setdefault(legacy_owner, set()).add(path)
    expected_owner_paths = {object_id: set() for object_id in expected}
    observed_surface_paths: dict[str, str] = {}
    for surface in observed.get("surfaces", ()):
        if (
            type(surface) is not dict
            or type(surface.get("path")) is not str
            or type(surface.get("surface_id")) is not str
        ):
            raise ValueError("PACKAGE_MIGRATION_DISCOVERED_SURFACE_INVALID")
        path = surface["path"]
        surface_id = surface["surface_id"]
        observed_surface_paths[surface_id] = path
        owner = _owner_for_path(
            path,
            by_kind,
            semantic_owners if installed_specs else None,
        )
        expected_owner_paths.setdefault(owner, set()).add(path)

    reviews: dict[str, dict] = {}
    review_owners: dict[str, object] = {}
    for review_module in _PACKAGE_REVIEW_MODULES:
        for object_id, review in review_module.review_document().items():
            if object_id in reviews:
                raise ValueError("PACKAGE_MIGRATION_REVIEW_CATALOG_OVERLAP")
            reviews[object_id] = review
            review_owners[object_id] = review_module

    # The source-semantic profile is the explicit lifecycle marker for a
    # repository whose complete source-owned semantic ownership catalog has
    # already been installed.  Neither a row count nor one reviewed decision
    # is sufficient: both are attacker-controlled predecessor data.  Require
    # the exact current catalog and the structurally bound GRAPH adapter before
    # treating UNRESOLVED as a forbidden rollback rather than a pristine
    # bootstrap state.
    catalog_ids = set(specs)
    full_semantic_catalog = bool(catalog_ids) and set(installed_specs) == catalog_ids
    if full_semantic_catalog and not install_semantic_ownership:
        validated_specs = {
            spec.object_id: spec
            for spec in package_semantic_ownership.validate_catalog(root)
        }
        if validated_specs != specs:
            raise ValueError(
                "PACKAGE_MIGRATION_PREDECESSOR_SEMANTIC_CATALOG_DIFFERS"
            )

    def carries_exact_predecessor_paths(
        object_id: str, carried: set[str], required: set[str]
    ) -> bool:
        """Accept only current routing or its exact pre-install fallback."""

        legacy = legacy_pending_paths.get(object_id, set())
        return required <= carried <= required | legacy

    package_graph_id = by_kind["GRAPH"]
    package_graph = rows_by_id[package_graph_id]
    graph_payload = package_graph.get("payload")
    graph_claims_mature_profile = (
        type(graph_payload) is dict
        and "source_semantic_profile" in graph_payload
    )
    mature_review_lifecycle = full_semantic_catalog and graph_claims_mature_profile
    if mature_review_lifecycle:
        try:
            _validate_package_graph_adapter_basis(
                document["namespace"],
                registry,
                package_graph_id,
                document.get("representation_updates", []),
                files,
                permit_stale_sha=permit_stale_sha,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(
                "PACKAGE_MIGRATION_PREDECESSOR_LIFECYCLE_GRAPH_DIFFERS"
            ) from exc

    for object_id, row in rows_by_id.items():
        shape = expected.get(object_id)
        if shape is None:
            raise ValueError(
                "PACKAGE_MIGRATION_PREDECESSOR_OBJECT_ID_UNRECOGNIZED:"
                + object_id
            )
        if row["kind"] != shape["kind"]:
            raise ValueError(
                "PACKAGE_MIGRATION_PREDECESSOR_PRIMARY_KIND_DIFFERS:"
                + object_id
            )

        spec = shape["installed_spec"]
        surfaces = row.get("surfaces")
        if (
            type(surfaces) is not list
            or len(surfaces) != len(set(surfaces))
            or any(type(surface) is not str for surface in surfaces)
        ):
            raise ValueError(
                "PACKAGE_MIGRATION_PREDECESSOR_SURFACES_DIFFER:" + object_id
            )
        carried_surface_paths: set[str] = set()
        for surface in surfaces:
            path = observed_surface_paths.get(surface)
            if path is None:
                if surface.startswith("file:"):
                    path = surface.removeprefix("file:")
                elif ":" in surface:
                    path = surface.split(":", 2)[1]
            if not path:
                raise ValueError(
                    "PACKAGE_MIGRATION_PREDECESSOR_SURFACES_DIFFER:" + object_id
                )
            carried_surface_paths.add(path)
        if spec is not None:
            current_payload = {"representation_role": spec.representation_role}
            prior_role = _PRE_APPLICABILITY_REPRESENTATION_ROLES.get(object_id)
            prior_payload = (
                {"representation_role": prior_role}
                if prior_role is not None
                else None
            )
            if row.get("payload") not in (current_payload, prior_payload):
                raise ValueError(
                    "PACKAGE_MIGRATION_PREDECESSOR_PAYLOAD_DIFFERS:" + object_id
                )
            expected_reason = (
                spec.necessity_reason + " Boundary: " + spec.consequence_boundary
            )
            if row.get("reason") != expected_reason:
                raise ValueError(
                    "PACKAGE_MIGRATION_PREDECESSOR_OBJECT_REASON_DIFFERS:"
                    + object_id
                )
            current_paths = set(spec.owned_paths)
            prior_paths = current_paths - set(
                _PRE_APPLICABILITY_MISSING_OWNED_PATHS.get(object_id, ())
            )
            if not any(
                carries_exact_predecessor_paths(
                    object_id, carried_surface_paths, expected_paths
                )
                for expected_paths in (current_paths, prior_paths)
            ):
                raise ValueError(
                    "PACKAGE_MIGRATION_PREDECESSOR_SURFACES_DIFFER:" + object_id
                )
        elif "named_paths" in shape:
            expected_paths = expected_owner_paths.get(object_id, set())
            if not carries_exact_predecessor_paths(
                object_id, carried_surface_paths, expected_paths
            ):
                raise ValueError(
                    "PACKAGE_MIGRATION_PREDECESSOR_SURFACES_DIFFER:" + object_id
                )
            named_paths = sorted(shape["named_paths"])
            expected_payload = {
                "representation_role": "Exact source group: "
                + ", ".join(named_paths)
            }
            expected_reason = (
                "The exact source group has an explicit "
                + shape["kind"]
                + " boundary."
            )
            _select_named_metadata_transition(
                object_id,
                row,
                current_payload=expected_payload,
                current_reason=expected_reason,
                refresh_reviewed=permit_stale_sha,
                select_package_namespace_review=select_package_namespace_review,
            )
        else:
            expected_paths = expected_owner_paths.get(object_id, set())
            if not carries_exact_predecessor_paths(
                object_id, carried_surface_paths, expected_paths
            ):
                raise ValueError(
                    "PACKAGE_MIGRATION_PREDECESSOR_SURFACES_DIFFER:" + object_id
                )
            retained_payload = shape["retained_payload"]
            payload = row.get("payload")
            if shape["kind"] == "GRAPH" and payload != retained_payload:
                try:
                    _validate_package_graph_adapter_basis(
                        document["namespace"],
                        registry,
                        object_id,
                        document.get("representation_updates", []),
                        files,
                        permit_stale_sha=permit_stale_sha,
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    raise ValueError(
                        "PACKAGE_MIGRATION_PREDECESSOR_PAYLOAD_DIFFERS:"
                        + object_id
                    ) from exc
            elif shape["kind"] == "HARNESS":
                if (
                    type(payload) is not dict
                    or payload.get("representation_role")
                    != retained_payload["representation_role"]
                    or set(payload)
                    - {"representation_role", "direct_launch_denominator"}
                ):
                    raise ValueError(
                        "PACKAGE_MIGRATION_PREDECESSOR_PAYLOAD_DIFFERS:"
                        + object_id
                    )
                try:
                    package_harness_applicability.declarations_from_manifest_owner(
                        row
                    )
                except ValueError as exc:
                    raise ValueError(
                        "PACKAGE_MIGRATION_PREDECESSOR_PAYLOAD_DIFFERS:"
                        + object_id
                    ) from exc
            elif payload != retained_payload:
                raise ValueError(
                    "PACKAGE_MIGRATION_PREDECESSOR_PAYLOAD_DIFFERS:" + object_id
                )
            if row.get("reason") != (
                "Retained package role: "
                + shape["retained_role"]
                + ". Source ownership enumerates its representation; "
                "operational truth remains a higher-tier question."
            ):
                raise ValueError(
                    "PACKAGE_MIGRATION_PREDECESSOR_OBJECT_REASON_DIFFERS:"
                    + object_id
                )

        review = reviews.get(object_id, {})
        expected_decisions = {
            kind: {
                "status": decision["status"],
                "reason": decision["reason"],
                "evidence_paths": set(decision["evidence_paths"]),
            }
            for kind, decision in reviews.get(object_id, {}).get(
                "classification", {}
            ).items()
        }
        primary_kind = shape["kind"]
        if _is_original_primary_kind(registry, primary_kind):
            expected_decisions[primary_kind] = {
                "status": "APPLIES",
                "reason": _primary_original_kind_reason(
                    primary_kind, row["reason"]
                ),
                # Validate against the predecessor's exact accepted ownership
                # denominator. During an explicit semantic-owner install this
                # may be the finite pre-install path set; its surfaces were
                # already checked above against the only permitted transition.
                "evidence_paths": set(carried_surface_paths),
            }
        if spec is not None:
            for decision in spec.root_role_decisions:
                expected_decisions[decision.kind] = {
                    "status": decision.status,
                    "reason": decision.reason,
                    "evidence_paths": set(spec.owned_paths),
                }
        classification = row["classification"]
        compact_decision_ids = set(expected_decisions)
        full_decision_ids = set(registry) - {"OBJECT"}
        classification_ids = set(classification)
        if classification_ids == full_decision_ids:
            for kind in full_decision_ids - compact_decision_ids:
                expected_decisions[kind] = {
                    "status": "UNRESOLVED",
                    "reason": (
                        "Migration retains this applicability question. Static "
                        "ownership alone cannot refute a " + kind + " role."
                    ),
                    "evidence_paths": set(),
                }
        elif classification_ids != compact_decision_ids:
            raise ValueError(
                "PACKAGE_MIGRATION_PREDECESSOR_CLASSIFICATION_IDENTITIES_DIFFER:"
                + object_id
            )

        recognized_classification = (
            value_digest(
                _review_projection(classification, classification=True)
            )
            == _PRE_APPLICABILITY_CLASSIFICATION_PROJECTIONS.get(object_id)
        )
        expected_specializations = set(shape["specializations"])
        for kind, decision in classification.items():
            status = decision["status"]
            expected_decision = expected_decisions[kind]
            if status == "UNRESOLVED":
                # Once both mature lifecycle anchors are present, the current
                # profile is evidence for maturity, not authority over which
                # reviews exist.  The source-owned review catalog supplies
                # that denominator so deleting and resealing one profile
                # binding cannot turn a reviewed answer back into bootstrap.
                if (
                    mature_review_lifecycle
                    and expected_decision["status"] != "UNRESOLVED"
                ):
                    raise ValueError(
                        "PACKAGE_MIGRATION_PREDECESSOR_CLASSIFICATION_DIFFERS:"
                        + object_id
                        + ":"
                        + kind
                    )
                expected_unresolved_reason = (
                    "Migration retains this applicability question. Static "
                    "ownership alone cannot refute a " + kind + " role."
                )
                if decision.get("reason") not in {
                    expected_unresolved_reason,
                    _compiled_classification_reason(
                        "UNRESOLVED", expected_unresolved_reason
                    ),
                }:
                    raise ValueError(
                        "PACKAGE_MIGRATION_PREDECESSOR_CLASSIFICATION_DIFFERS:"
                        + object_id
                        + ":"
                        + kind
                    )
                _evidence_paths(
                    decision.get("evidence"),
                    expected=set(),
                    files=files,
                    permit_stale_sha=permit_stale_sha,
                    error=(
                        "PACKAGE_MIGRATION_PREDECESSOR_"
                        "CLASSIFICATION_EVIDENCE_PATHS_DIFFER:"
                        + object_id
                        + ":"
                        + kind
                    ),
                )
                continue
            if not recognized_classification and (
                status != expected_decision["status"]
                or decision.get("reason")
                not in {
                    expected_decision["reason"],
                    _compiled_classification_reason(
                        expected_decision["status"],
                        expected_decision["reason"],
                    ),
                }
            ):
                raise ValueError(
                    "PACKAGE_MIGRATION_PREDECESSOR_CLASSIFICATION_DIFFERS:"
                    + object_id
                    + ":"
                    + kind
                )
            evidence_paths = expected_decision["evidence_paths"]
            if recognized_classification:
                evidence_paths = {
                    reference["path"]
                    for reference in decision.get("evidence", ())
                    if isinstance(reference, dict) and "path" in reference
                }
            elif spec is not None:
                evidence_paths -= set(
                    _PRE_APPLICABILITY_MISSING_OWNED_PATHS.get(object_id, ())
                )
            else:
                evidence_paths &= carried_surface_paths
            _evidence_paths(
                decision.get("evidence"),
                expected=evidence_paths,
                files=files,
                permit_stale_sha=permit_stale_sha,
                error=(
                    "PACKAGE_MIGRATION_PREDECESSOR_"
                    "CLASSIFICATION_EVIDENCE_PATHS_DIFFER:"
                    + object_id
                    + ":"
                    + kind
                ),
            )
            # Root-role decisions may name another legacy base kind (for
            # example DATA carrying a RECEIPT consequence). Base kinds are
            # classifications, not refinement labels; only registered
            # extensions can appear in ``specializations``.
            if (
                status == "APPLIES"
                and kind != row["kind"]
                and registry[kind].extends is not None
            ):
                expected_specializations.add(kind)
        expected_specializations.discard(row["kind"])
        if set(row["specializations"]) != expected_specializations:
            raise ValueError(
                "PACKAGE_MIGRATION_PREDECESSOR_SPECIALIZATIONS_DIFFER:"
                + object_id
            )
        if object_id != "vstd-package-graph" and row["operands"] != shape["operands"]:
            raise ValueError(
                "PACKAGE_MIGRATION_PREDECESSOR_OPERANDS_DIFFER:" + object_id
            )

        obligations = {
            item["id"]: set(item["declaration_fields"])
            for item in namespace_contracts.requirements_for(
                registry, {row["kind"], *row["specializations"]}
            )
        }
        if set(row["obligations"]) != set(obligations):
            raise ValueError(
                "PACKAGE_MIGRATION_PREDECESSOR_OBLIGATION_IDENTITIES_DIFFER:"
                + object_id
            )
        recognized_obligations = (
            value_digest(
                _review_projection(row["obligations"], classification=False)
            )
            == _PRE_APPLICABILITY_OBLIGATION_PROJECTIONS.get(object_id)
        )
        declarations = review.get("declarations", {})
        review_owner = review_owners.get(object_id)
        for obligation_id, binding in row["obligations"].items():
            if set(binding.get("declaration", {})) != obligations[obligation_id]:
                raise ValueError(
                    "PACKAGE_MIGRATION_PREDECESSOR_DECLARATION_FIELDS_DIFFER:"
                    + object_id
                    + ":"
                    + obligation_id
                )
            expected_declaration = declarations.get(obligation_id)
            populated = bool(binding.get("reason", "").strip()) or any(
                type(value) is str and bool(value.strip())
                for value in binding.get("declaration", {}).values()
            )
            if expected_declaration is None:
                if populated:
                    raise ValueError(
                        "PACKAGE_MIGRATION_PREDECESSOR_DECLARATION_VALUES_DIFFER:"
                        + object_id
                        + ":"
                        + obligation_id
                    )
                _evidence_paths(
                    binding.get("evidence"),
                    expected=set(),
                    files=files,
                    permit_stale_sha=permit_stale_sha,
                    error=(
                        "PACKAGE_MIGRATION_PREDECESSOR_"
                        "OBLIGATION_EVIDENCE_PATHS_DIFFER:"
                        + object_id
                        + ":"
                        + obligation_id
                    ),
                )
                continue
            kind = obligation_id.split("-", 1)[0]
            expected_decision = expected_decisions[kind]
            if obligation_id in reviewed_declarations(object_id):
                expected_reason = (
                    "The owned implementation requires this explicit boundary; "
                    "the declaration does not claim execution correctness."
                )
            else:
                expected_reason = expected_decision["reason"] + (
                    _PACKAGE_REVIEW_OBLIGATION_SUFFIXES[review_owner]
                )
            if not recognized_obligations and binding.get("reason") != expected_reason:
                raise ValueError(
                    "PACKAGE_MIGRATION_PREDECESSOR_OBLIGATION_REASON_DIFFERS:"
                    + object_id
                    + ":"
                    + obligation_id
                )
            if (
                not recognized_obligations
                and binding.get("declaration") != expected_declaration
            ):
                raise ValueError(
                    "PACKAGE_MIGRATION_PREDECESSOR_DECLARATION_VALUES_DIFFER:"
                    + object_id
                    + ":"
                    + obligation_id
                )
            evidence_paths = set(expected_decision["evidence_paths"])
            if recognized_obligations:
                evidence_paths = {
                    reference["path"]
                    for reference in binding.get("evidence", ())
                    if isinstance(reference, dict) and "path" in reference
                }
            elif spec is not None:
                evidence_paths -= set(
                    _PRE_APPLICABILITY_MISSING_OWNED_PATHS.get(object_id, ())
                )
            else:
                evidence_paths &= carried_surface_paths
            _evidence_paths(
                binding.get("evidence"),
                expected=evidence_paths,
                files=files,
                permit_stale_sha=permit_stale_sha,
                error=(
                    "PACKAGE_MIGRATION_PREDECESSOR_"
                    "OBLIGATION_EVIDENCE_PATHS_DIFFER:"
                    + object_id
                    + ":"
                    + obligation_id
                ),
            )

def _pre_applicability_tier_zero_profile_digest(profile: dict) -> str:
    """Derive the exact nine-obligation profile before applicability fields."""

    body = {key: deepcopy(value) for key, value in profile.items()
            if key != "profile_digest"}
    for obligation in body["obligations"]:
        if set(("applicability", "applicability_digest")) - set(obligation):
            raise ValueError("PACKAGE_MIGRATION_PROFILE_PREDECESSOR_UNAVAILABLE")
        obligation.pop("applicability")
        obligation.pop("applicability_digest")
    return value_digest(body)


def _validate_current_or_pre_applicability_profile(
    retained: dict,
    *,
    expected_repository: str,
    expected_revision: str,
) -> dict:
    """Validate Tier zero or upgrade only its exact applicability predecessor."""

    try:
        tier_zero_manifest.validate_manifest(
            retained,
            expected_repository=expected_repository,
            expected_revision=expected_revision,
        )
        return retained
    except tier_zero_manifest.TierZeroManifestError as exc:
        if str(exc) != "TIER_ZERO_MANIFEST_PROFILE_DIFFERS":
            raise

    profile = tier_zero_profile.installed_tier_zero_profile()
    if retained.get("profile_digest") != _pre_applicability_tier_zero_profile_digest(
        profile
    ):
        raise tier_zero_manifest.TierZeroManifestError(
            "TIER_ZERO_MANIFEST_PROFILE_DIFFERS"
        )
    upgraded = deepcopy(retained)
    upgraded["profile_digest"] = profile["profile_digest"]
    tier_zero_manifest.validate_manifest(
        upgraded,
        expected_repository=expected_repository,
        expected_revision=expected_revision,
    )
    return upgraded


def _pre_verifier_core_harness_objects() -> list[dict[str, Any]]:
    """Return the one retained graph predecessor before the core HARNESS edge."""

    rows = deepcopy(tier_zero_manifest.installed_object_declarations())
    matches = [
        row for row in rows if row.get("object_id") == "verifier-core-self"
    ]
    if len(matches) != 1 or matches[0].get("edges") != {
        "harness": ["vstd-harness"]
    }:
        raise RuntimeError("PACKAGE_MIGRATION_CORE_HARNESS_TEMPLATE_DIFFERS")
    matches[0]["edges"] = {}
    return rows


def _is_exact_verifier_core_harness_retained_transition(
    before: object,
    after: object,
) -> bool:
    """Recognize only the additive retained edge selected by the installed graph."""

    if type(before) is not dict or type(after) is not dict:
        return False
    prior = deepcopy(before)
    current = deepcopy(after)
    if (
        prior.get("objects") != _pre_verifier_core_harness_objects()
        or current.get("objects")
        != tier_zero_manifest.installed_object_declarations()
    ):
        return False
    prior["objects"] = deepcopy(current["objects"])
    return prior == current


def _upgrade_current_or_pre_verifier_core_harness_binding(
    document: dict,
) -> dict:
    """Upgrade one exact admitted predecessor to the governing HARNESS edge.

    Both the retained graph and its namespace projection are validated before
    the sole additive mutation.  Any near miss is left untouched so the normal
    current validators reject it at its original boundary.
    """

    retained = package_manifest.retained_contract(document)
    current_objects = tier_zero_manifest.installed_object_declarations()
    if retained.get("objects") == current_objects:
        return document
    predecessor = _pre_verifier_core_harness_objects()
    if retained.get("objects") != predecessor:
        return document
    repository = retained.get("repository")
    if type(repository) is not dict:
        return document
    tier_zero_manifest.validate_manifest(
        retained,
        expected_repository=repository.get("remote"),
        expected_revision=repository.get("revision"),
        _installed_objects=predecessor,
    )
    package_manifest.validate_bridge(document)

    upgraded = deepcopy(document)
    retained_matches = [
        row
        for row in upgraded.get("objects", ())
        if type(row) is dict and row.get("object_id") == "verifier-core-self"
    ]
    namespace_matches = [
        row
        for row in upgraded.get("namespace", {}).get("objects", ())
        if type(row) is dict and row.get("object_id") == "verifier-core-self"
    ]
    if (
        len(retained_matches) != 1
        or retained_matches[0].get("edges") != {}
        or len(namespace_matches) != 1
        or namespace_matches[0].get("operands") != {}
    ):
        raise ValueError("PACKAGE_MIGRATION_CORE_HARNESS_PREDECESSOR_DIFFERS")
    binding = {"harness": ["vstd-harness"]}
    retained_matches[0]["edges"] = deepcopy(binding)
    namespace_matches[0]["operands"] = deepcopy(binding)
    return upgraded


def source_refresh_coordinate(root: Path) -> tuple[str, dict]:
    """Bind every candidate source input except the manifest transaction target."""

    git_coordinate = self_polish_estate._git_coordinate(root)
    census = self_polish_estate.capture_candidate_source_census(
        root, allow_untracked_only=True
    )
    if self_polish_estate._git_coordinate(root) != git_coordinate:
        raise self_polish_estate.EstateError("GIT_COORDINATE_INVALID")
    body = {
        "schema_version": census.get("schema_version"),
        "selection": census.get("selection"),
        "git_coordinate": git_coordinate,
        "git_index_digest": census.get("git_index_digest"),
        "git_status_digest": census.get("git_status_digest"),
        "files": [
            row for row in census.get("files", [])
            if row.get("path") != "objects.vstd"
        ],
        "ignored_scan": census.get("ignored_scan"),
    }
    return value_digest(body), body


SOURCE_SEMANTIC_PROFILE_SCHEMA = "verifier-source-semantic-review-profile-1"


def source_semantic_identity(root: Path, path: str) -> dict[str, str]:
    """Return a dependency-free semantic identity for one reviewed source.

    Python's location-free abstract syntax tree permits comment, whitespace and
    line-movement refreshes. Other source types remain byte-exact until their
    language extension provides an equally bounded parser.
    """

    candidate = (root / path).resolve(strict=True)
    if root != candidate and root not in candidate.parents:
        raise ValueError("PACKAGE_SOURCE_SEMANTIC_PATH_ESCAPES_ROOT")
    raw = candidate.read_bytes()
    if candidate.suffix in {".py", ".pyi"}:
        try:
            tree = ast.parse(raw.decode("utf-8"), filename=path)
        except (SyntaxError, UnicodeError) as exc:
            raise ValueError(
                "PACKAGE_SOURCE_SEMANTIC_PYTHON_INVALID:" + path
            ) from exc
        semantic_kind = "python-location-free-ast"
        semantic_raw = ast.dump(
            tree, annotate_fields=True, include_attributes=False
        ).encode("utf-8")
    else:
        semantic_kind = "byte-exact"
        semantic_raw = raw
    return {
        "source_sha256": bytes_digest(raw),
        "semantic_kind": semantic_kind,
        "semantic_sha256": bytes_digest(semantic_raw),
    }


_PARALLEL_SEMANTIC_PROFILE_THRESHOLD = 128
_MAX_SEMANTIC_PROFILE_WORKERS = 8


def _semantic_profile_identity_task(
    task: tuple[str, str],
) -> tuple[str, dict[str, str]]:
    root, path = task
    return path, source_semantic_identity(Path(root), path)


def _semantic_profile_identities(
    root: Path, paths: list[str],
) -> dict[str, dict[str, str]]:
    tasks = [(str(root), path) for path in paths]
    workers = min(
        _MAX_SEMANTIC_PROFILE_WORKERS,
        os.cpu_count() or 1,
        len(tasks),
    )
    if len(tasks) < _PARALLEL_SEMANTIC_PROFILE_THRESHOLD or workers == 1:
        return dict(_semantic_profile_identity_task(task) for task in tasks)
    with ProcessPoolExecutor(
        max_workers=workers,
        mp_context=multiprocessing.get_context("spawn"),
    ) as executor:
        return dict(
            executor.map(_semantic_profile_identity_task, tasks, chunksize=4)
        )


def source_semantic_profile(root: Path, rows: dict[str, dict]) -> dict:
    """Bind reviewed answers to exact path semantics and affected questions."""

    bindings: dict[str, dict[str, dict[str, set[str]]]] = {}
    for object_id, row in rows.items():
        for kind, decision in row.get("classification", {}).items():
            if decision.get("status") == "UNRESOLVED":
                continue
            for evidence in decision.get("evidence", []):
                path = evidence.get("path")
                if type(path) is not str:
                    continue
                object_binding = bindings.setdefault(path, {}).setdefault(
                    object_id, {"classifications": set(), "obligations": set()}
                )
                object_binding["classifications"].add(kind)
        for obligation_id, obligation in row.get("obligations", {}).items():
            complete = bool(obligation.get("reason", "").strip()) or any(
                type(value) is str and bool(value.strip())
                for value in obligation.get("declaration", {}).values()
            )
            if not complete:
                continue
            for evidence in obligation.get("evidence", []):
                path = evidence.get("path")
                if type(path) is not str:
                    continue
                object_binding = bindings.setdefault(path, {}).setdefault(
                    object_id, {"classifications": set(), "obligations": set()}
                )
                object_binding["obligations"].add(obligation_id)

    selected_paths = sorted(bindings)
    identities = _semantic_profile_identities(root, selected_paths)
    expanded_paths = []
    for path, object_bindings in sorted(bindings.items()):
        expanded_paths.append({
            "path": path,
            **identities[path],
            "bindings": [
                {
                    "object_id": object_id,
                    "classifications": sorted(binding["classifications"]),
                    "obligations": sorted(binding["obligations"]),
                }
                for object_id, binding in sorted(object_bindings.items())
            ],
        })
    binding_sets_by_digest = {
        value_digest(row["bindings"]): canonical_bytes(row["bindings"]).decode("utf-8")
        for row in expanded_paths
    }
    binding_set_digests = sorted(binding_sets_by_digest)
    binding_set_indexes = {
        digest: index for index, digest in enumerate(binding_set_digests)
    }
    records = [
        "\t".join((
            row["path"],
            row["semantic_kind"],
            row["semantic_sha256"],
            str(binding_set_indexes[value_digest(row["bindings"])]),
        ))
        for row in expanded_paths
    ]
    body = {
        "schema_version": SOURCE_SEMANTIC_PROFILE_SCHEMA,
        "reason": (
            "Reviewed applicability and obligation answers may be rebound "
            "automatically only when their evidence retains the same bounded "
            "semantics; non-Python languages remain byte-exact until a selected "
            "language parser proves a narrower equivalence."
        ),
        "binding_sets": [binding_sets_by_digest[digest]
                         for digest in binding_set_digests],
        "records": records,
    }
    return {**body, "digest": value_digest(body)}


def _package_review_refresh_catalog() -> dict[str, dict[str, frozenset[str]]]:
    """Return the exact binding keys owned by the complete selected review set.

    ``--refresh-reviewed`` may replace only these catalog-owned answers before
    the same review modules re-evaluate current source.  Other roles, receipts,
    execution selections, and independently authored bindings remain untouched.
    """

    registry = namespace_contracts.namespace_registry()
    own_obligations = {
        kind: frozenset(
            obligation["id"]
            for obligation in namespace_contracts.requirements_for(registry, {kind})
            if obligation["kind"] == kind
        )
        for kind in registry
    }
    catalog: dict[str, dict[str, frozenset[str]]] = {}
    for module in _PACKAGE_REVIEW_MODULES:
        document = module.review_document()
        if type(document) is not dict:
            raise ValueError("PACKAGE_MIGRATION_REVIEW_CATALOG_INVALID")
        for object_id, review in document.items():
            if object_id in catalog or type(review) is not dict:
                raise ValueError("PACKAGE_MIGRATION_REVIEW_CATALOG_OVERLAP")
            classification = review.get("classification")
            declarations = review.get("declarations")
            if type(classification) is not dict or type(declarations) is not dict:
                raise ValueError("PACKAGE_MIGRATION_REVIEW_CATALOG_INVALID")
            # Refresh owns the complete answer for every reviewed kind, not
            # merely declarations emitted by APPLIES rows.  If a current
            # source review refutes a formerly applicable kind, its prior
            # active obligations must leave the current denominator or the
            # manifest contradicts its own evidenced refutation.  The external
            # migration backup retains the historical declaration bytes.
            refreshed_obligations = set(declarations)
            for kind in classification:
                refreshed_obligations.update(own_obligations[kind])
            refreshed_classification = set(classification)
            primary_kind = review.get("primary_kind")
            if (
                type(primary_kind) is str
                and primary_kind in registry
                and _is_original_primary_kind(registry, primary_kind)
            ):
                refreshed_classification.add(primary_kind)
            catalog[object_id] = {
                "classification": frozenset(refreshed_classification),
                "obligations": frozenset(refreshed_obligations),
            }
    # Root-role decisions are authored by the same exact ownership catalog but
    # sit outside the twelve additive consequence-kind review matrices.  They
    # must refresh with their owner's current byte denominator; preserving an
    # older answer here makes an explicit APPLIES/refutation fail freshness.
    for spec in package_semantic_ownership.SEMANTIC_OWNERSHIP_SPECS:
        if not spec.root_role_decisions:
            continue
        try:
            current = catalog[spec.object_id]
        except KeyError as exc:
            raise ValueError("PACKAGE_MIGRATION_REVIEW_CATALOG_INCOMPLETE") from exc
        current["classification"] = frozenset(
            set(current["classification"])
            | {decision.kind for decision in spec.root_role_decisions}
        )
    return catalog


def _manifest_reference_paths(references: object) -> set[str] | None:
    """Return a unique evidence path set only for well-formed references."""

    if type(references) is not list:
        return None
    paths: list[str] = []
    for reference in references:
        if (
            type(reference) is not dict
            or set(reference) != {"path", "sha256"}
            or type(reference.get("path")) is not str
            or type(reference.get("sha256")) is not str
        ):
            return None
        paths.append(reference["path"])
    if len(paths) != len(set(paths)):
        return None
    return set(paths)


def _installed_package_review_ids(rows: object) -> set[str]:
    """Recognize selected reviews by their full current manifest shape."""

    if type(rows) is not list:
        return set()
    review_catalog_ids = set(_package_review_refresh_catalog())
    catalog_rows = [
        row
        for row in rows
        if type(row) is dict and row.get("object_id") in review_catalog_ids
    ]
    if len(catalog_rows) != len({row["object_id"] for row in catalog_rows}):
        return set()
    rows_by_id = {
        row.get("object_id"): row
        for row in rows
        if type(row) is dict and type(row.get("object_id")) is str
    }
    installed: set[str] = set()
    for review_module in _PACKAGE_REVIEW_MODULES:
        for object_id, review in review_module.review_document().items():
            row = rows_by_id.get(object_id)
            if type(row) is not dict or row.get("kind") != review.get("primary_kind"):
                continue
            surfaces = row.get("surfaces")
            if type(surfaces) is not list or {
                surface.removeprefix("file:")
                for surface in surfaces
                if type(surface) is str and surface.startswith("file:")
            } != set(review.get("owned_paths", ())):
                continue
            classification = row.get("classification")
            obligations = row.get("obligations")
            if type(classification) is not dict or type(obligations) is not dict:
                continue
            complete = True
            for kind, expected in review.get("classification", {}).items():
                decision = classification.get(kind)
                if (
                    type(decision) is not dict
                    or decision.get("status") != expected.get("status")
                    or decision.get("reason") != expected.get("reason")
                    or _manifest_reference_paths(decision.get("evidence"))
                    != set(expected.get("evidence_paths", ()))
                ):
                    complete = False
                    break
            if not complete:
                continue
            for obligation_id, declaration in review.get("declarations", {}).items():
                binding = obligations.get(obligation_id)
                kind = obligation_id.split("-", 1)[0]
                expected_paths = set(
                    review["classification"][kind].get("evidence_paths", ())
                )
                if (
                    type(binding) is not dict
                    or type(binding.get("reason")) is not str
                    or not binding["reason"].strip()
                    or binding.get("declaration") != declaration
                    or _manifest_reference_paths(binding.get("evidence"))
                    != expected_paths
                ):
                    complete = False
                    break
            if complete:
                installed.add(object_id)
    return installed


def _source_semantic_profile_matches_rows(profile: object, rows: object) -> bool:
    """Bind a selected profile to every evidenced answer in its manifest."""

    if type(profile) is not dict or type(rows) is not list:
        return False
    try:
        decoded_sets = [json.loads(encoded) for encoded in profile["binding_sets"]]
    except (KeyError, TypeError, ValueError):
        return False
    profiled: dict[str, object] = {}
    try:
        for record in profile["records"]:
            path, _, _, binding_index = record.split("\t")
            profiled[path] = decoded_sets[int(binding_index)]
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return False

    bindings: dict[str, dict[str, dict[str, set[str]]]] = {}
    for row in rows:
        if type(row) is not dict or type(row.get("object_id")) is not str:
            return False
        object_id = row["object_id"]
        classification = row.get("classification", {})
        obligations = row.get("obligations", {})
        if type(classification) is not dict or type(obligations) is not dict:
            return False
        for kind, decision in classification.items():
            if type(decision) is not dict or decision.get("status") == "UNRESOLVED":
                continue
            paths = _manifest_reference_paths(decision.get("evidence"))
            if paths is None:
                return False
            for path in paths:
                binding = bindings.setdefault(path, {}).setdefault(
                    object_id, {"classifications": set(), "obligations": set()}
                )
                binding["classifications"].add(kind)
        for obligation_id, obligation in obligations.items():
            if type(obligation) is not dict:
                continue
            reason = obligation.get("reason")
            declaration = obligation.get("declaration", {})
            if type(declaration) is not dict:
                return False
            complete = (
                type(reason) is str and bool(reason.strip())
            ) or any(
                type(value) is str and bool(value.strip())
                for value in declaration.values()
            )
            if not complete:
                continue
            paths = _manifest_reference_paths(obligation.get("evidence"))
            if paths is None:
                return False
            for path in paths:
                binding = bindings.setdefault(path, {}).setdefault(
                    object_id, {"classifications": set(), "obligations": set()}
                )
                binding["obligations"].add(obligation_id)
    expected = {
        path: [
            {
                "object_id": object_id,
                "classifications": sorted(binding["classifications"]),
                "obligations": sorted(binding["obligations"]),
            }
            for object_id, binding in sorted(object_bindings.items())
        ]
        for path, object_bindings in sorted(bindings.items())
    }
    return profiled == expected


def _validate_source_semantic_refresh(root: Path, document: dict) -> None:
    """Refuse to reseal reviewed answers after unreviewed semantic drift."""

    rows = document.get("namespace", {}).get("objects", [])
    graph = next(
        (
            row
            for row in rows
            if type(row) is dict and row.get("object_id") == "vstd-package-graph"
        ),
        None,
    )
    try:
        profile = _validated_source_semantic_profile(
            graph["payload"]["source_semantic_profile"]
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            "PACKAGE_MIGRATION_SOURCE_SEMANTIC_PROFILE_DIFFERS"
        ) from exc
    if not _source_semantic_profile_matches_rows(profile, rows):
        raise ValueError("PACKAGE_MIGRATION_SOURCE_SEMANTIC_PROFILE_DIFFERS")
    for record in profile["records"]:
        path, semantic_kind, semantic_sha256, _ = record.split("\t")
        try:
            current = source_semantic_identity(root, path)
        except (FileNotFoundError, OSError, ValueError) as exc:
            raise ValueError(
                "PACKAGE_MIGRATION_SOURCE_SEMANTICS_CHANGED:" + path
            ) from exc
        if (
            current["semantic_kind"] != semantic_kind
            or current["semantic_sha256"] != semantic_sha256
        ):
            raise ValueError("PACKAGE_MIGRATION_SOURCE_SEMANTICS_CHANGED:" + path)


def _has_authored_text(binding: dict[str, Any]) -> bool:
    """Whether an obligation binding carries reviewed text rather than a blank shell."""

    return bool(binding.get("reason")) or any(
        binding.get("declaration", {}).values()
    )


def _reopen_rows(
    rows: dict[str, dict],
    deltas: list[dict[str, Any]],
    previous: dict[str, dict] | None = None,
) -> list[dict[str, Any]]:
    """Reopen, in place, every inherited answer the deltas name; return one gap per delta.

    ``previous`` are the rows this pass started from.  A named cell that differs from
    its previous value was re-evaluated by the reviewed catalogs against the current
    bytes during this same pass, so it is the review's own current answer, not an
    inherited claim over bytes that changed meaning.  It is kept and reported as
    re-adopted; reopening it would only force a second pass to derive it again.  A
    cell still identical to its previous value is inherited and reopens.  Without
    ``previous`` every named answer reopens.
    """
    gaps: list[dict[str, Any]] = []
    for delta in sorted(deltas, key=lambda item: (item["path"], item["object_id"])):
        row = rows.get(delta["object_id"])
        prior = (previous or {}).get(delta["object_id"]) or {}
        readopted_classifications: set[str] = set()
        readopted_obligations: set[str] = set()
        if row is not None:
            reason = (
                "Reopened: the semantics of "
                + delta["path"]
                + " changed after this answer was reviewed, so it is not "
                "inherited and must be reviewed again."
            )
            for kind in delta["classifications"]:
                decision = row["classification"].get(kind)
                if decision is not None and decision.get("status") != "UNRESOLVED":
                    before = prior.get("classification", {}).get(kind)
                    if before is not None and decision != before:
                        readopted_classifications.add(kind)
                        continue
                    row["classification"][kind] = {
                        "status": "UNRESOLVED",
                        "reason": reason,
                        "evidence": [],
                    }
            for obligation_id in delta["obligations"]:
                binding = row["obligations"].get(obligation_id)
                if binding is not None:
                    before = prior.get("obligations", {}).get(obligation_id)
                    if (
                        before is not None
                        and binding != before
                        and _has_authored_text(binding)
                    ):
                        readopted_obligations.add(obligation_id)
                        continue
                    row["obligations"][obligation_id] = {
                        "reason": "",
                        "evidence": [],
                        "declaration": {
                            field: "" for field in binding.get("declaration", {})
                        },
                    }
        gap = {
            "stage": "source_semantics",
            "gap": "SOURCE_SEMANTICS_CHANGED",
            "path": delta["path"],
            "object_id": delta["object_id"],
            "classifications": sorted(
                set(delta["classifications"]) - readopted_classifications
            ),
            "obligations": sorted(
                set(delta["obligations"]) - readopted_obligations
            ),
        }
        if readopted_classifications or readopted_obligations:
            gap["readopted_classifications"] = sorted(readopted_classifications)
            gap["readopted_obligations"] = sorted(readopted_obligations)
        gaps.append(gap)
    return gaps


def reopen_changed_source_answers(
    root: Path,
    document: dict,
    deltas: list[dict[str, Any]],
) -> tuple[dict, list[dict[str, Any]]]:
    """Reopen each reviewed answer bound to a source whose semantics changed.

    ``deltas`` are the refresh's own review-required entries (path, object,
    classification kinds, obligation ids).  A reviewed answer is a closed claim over
    the bytes it cited, so once those bytes change meaning it is not inherited: the
    applicability decision becomes UNRESOLVED and the obligation loses its authored
    text, exactly as if it had never been answered.  Nothing is refuted or
    approved here.  The source profile is regenerated over the answers that remain,
    so the strict refresh gate then sees only unchanged evidence.  The input is not
    mutated; each reopened coordinate is reported as a gap.
    """
    if not deltas:
        return document, []
    reopened = deepcopy(document)
    rows = {row["object_id"]: row for row in reopened["namespace"]["objects"]}
    gaps = _reopen_rows(rows, deltas)
    graph = rows.get("vstd-package-graph")
    if graph is not None:
        graph["payload"]["source_semantic_profile"] = source_semantic_profile(
            root, rows
        )
    return reopened, gaps


def _merge_previous_binding_maps(
    row: dict,
    prior: dict,
    refreshed: dict[str, frozenset[str]],
) -> None:
    """Preserve every prior binding except exact keys selected for re-review."""

    for field in ("classification", "obligations"):
        excluded = refreshed.get(field, frozenset())
        row[field].update(
            {
                key: deepcopy(value)
                for key, value in prior[field].items()
                if key not in excluded
            }
        )


def _replace_structural_instance_checks(
    namespace: dict,
    registry: dict[str, namespace_contracts.KindContract],
) -> list[dict]:
    """Retire only checks superseded by the fresh whole-package facet replay.

    Additive package polish now executes both registered structural facets over
    every current manifest record and the current full collection.  Historical
    selected certificates bind an older collection and would otherwise override
    that stronger current-byte observation.  This explicit migration operation
    removes only routes whose installed scope is structural; domain, execution,
    and graph evidence (including GRAPH-3.1) remains selected.  The referenced
    evidence files are deliberately not deleted.
    """

    checks = namespace.get("instance_checks", [])
    by_id = {row["object_id"]: row for row in namespace["objects"]}
    retained: list[dict] = []
    replaced: list[dict] = []
    for check in checks:
        try:
            row = by_id[check["object_id"]]
            represented_kind = namespace_contracts.ancestors(
                registry, row["kind"]
            )[-1]
            route = current_object_routes.select_current_object_route(
                semantic_version=check["semantic_version"],
                objective=check["coordinate"],
                represented_kind=represented_kind,
            )
        except (
            KeyError,
            TypeError,
            current_object_routes.CurrentObjectRouteRefusal,
        ) as exc:
            raise ValueError(
                "PACKAGE_MIGRATION_INSTANCE_SELECTION_UNCLASSIFIABLE"
            ) from exc
        if check["proposition_digest"] != route.module.PROPOSITION_DIGEST:
            raise ValueError("PACKAGE_MIGRATION_INSTANCE_PROPOSITION_DIFFERS")
        if route.scope in STRUCTURAL:
            replaced.append(deepcopy(check))
        else:
            retained.append(deepcopy(check))
    namespace["instance_checks"] = retained
    return replaced


_PACKAGE_GRAPH_COORDINATE = "GRAPH-3.1"
_PACKAGE_GRAPH_REPLACEMENT = "fresh-source-bound-package-graph-replay"
_PACKAGE_GRAPH_ADAPTER_PAYLOAD_FIELDS = {
    "element_kind",
    "scope",
    "nodes_digest",
    "edges_digest",
    "source_refresh_coordinate",
    "source_semantic_profile",
}


def _is_sha256_digest(value: object) -> bool:
    return (
        type(value) is str
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def derived_package_graph_commitments(
    rows: dict[str, dict],
    registry: dict[str, namespace_contracts.KindContract],
    package_graph_id: str,
) -> dict[str, str] | None:
    """Project the final rows onto the package root's two dependency commitments.

    ``nodes_digest`` and ``edges_digest`` are projections of the member list and
    operand references, not reviewed judgements.  A root that does not declare both
    fields has nothing to derive and yields ``None``; rows that cannot be projected
    (an incomplete member list, an operand outside the package) raise ``ValueError``
    rather than being guessed at.  The caller's rows are never edited.
    """

    payload = rows[package_graph_id].get("payload")
    if (
        type(payload) is not dict
        or "nodes_digest" not in payload
        or "edges_digest" not in payload
    ):
        return None
    try:
        current: list[NamespaceObject] = []
        for row in rows.values():
            current_payload = deepcopy(row["payload"])
            current_kind = namespace_contracts.ancestors(registry, row["kind"])[-1]
            if current_kind == "GRAPH":
                current_payload["element_kind"] = namespace_contracts.ancestors(
                    registry, current_payload["element_kind"]
                )[-1]
            current.append(
                NamespaceObject.create(
                    row["object_id"], current_kind, current_payload, row["operands"]
                )
            )
        inputs = package_graph_representation.dependency_inputs(
            tuple(current), package_graph_id
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            "PACKAGE_MIGRATION_PACKAGE_GRAPH_DEPENDENCY_COMMITMENT_INVALID"
        ) from exc
    return {
        "nodes_digest": value_digest(inputs["nodes"]),
        "edges_digest": value_digest(inputs["edges"]),
    }


def _refresh_package_graph_dependency_commitments(
    rows: dict[str, dict],
    registry: dict[str, namespace_contracts.KindContract],
    package_graph_id: str,
) -> None:
    """Re-derive the enriched package root's declared dependency commitments.

    Migration adds and removes members, so carrying the previous arrays forward
    would leave the root declaring a dependency graph the same manifest no longer
    contains, and the fresh GRAPH adapter would then refute its own writer.
    """

    derived = derived_package_graph_commitments(rows, registry, package_graph_id)
    if derived is not None:
        rows[package_graph_id]["payload"].update(derived)


def _validate_package_graph_adapter_basis(
    namespace: dict,
    registry: dict[str, namespace_contracts.KindContract],
    package_graph_id: str,
    representation_updates: list[dict],
    files: dict[str, str],
    *,
    permit_stale_sha: bool = False,
) -> None:
    """Prove the would-be final manifest can use the fresh GRAPH adapter.

    Retirement is safe only after migration has produced the exact enriched
    package-root payload and refreshed representation update that the runtime
    adapter consumes.  The input update may legitimately be stale; this check
    therefore sees the final refreshed update and the current source census.
    """

    by_id = {row["object_id"]: row for row in namespace["objects"]}
    try:
        package_graph = by_id[package_graph_id]
        represented_kind = namespace_contracts.ancestors(
            registry, package_graph["kind"]
        )[-1]
    except (KeyError, TypeError) as exc:
        raise ValueError(
            "PACKAGE_MIGRATION_PACKAGE_GRAPH_RETIREMENT_UNCLASSIFIABLE"
        ) from exc
    if represented_kind != "GRAPH":
        raise ValueError(
            "PACKAGE_MIGRATION_PACKAGE_GRAPH_RETIREMENT_UNCLASSIFIABLE"
        )

    payload = package_graph.get("payload")
    if (
        type(payload) is not dict
        or set(payload) != _PACKAGE_GRAPH_ADAPTER_PAYLOAD_FIELDS
        or payload.get("element_kind") != "OBJECT"
        or payload.get("scope") != "retained_directed_graph"
        or not _is_sha256_digest(payload.get("nodes_digest"))
        or not _is_sha256_digest(payload.get("edges_digest"))
        or not _is_sha256_digest(payload.get("source_refresh_coordinate"))
    ):
        raise ValueError("PACKAGE_MIGRATION_PACKAGE_GRAPH_ADAPTER_PAYLOAD_INVALID")
    _validated_source_semantic_profile(payload["source_semantic_profile"])

    current_objects: list[NamespaceObject] = []
    for row in namespace["objects"]:
        current_payload = deepcopy(row["payload"])
        current_kind = namespace_contracts.ancestors(registry, row["kind"])[-1]
        if current_kind == "GRAPH":
            current_payload["element_kind"] = namespace_contracts.ancestors(
                registry, current_payload["element_kind"]
            )[-1]
        current_objects.append(
            NamespaceObject.create(
                row["object_id"],
                current_kind,
                current_payload,
                row["operands"],
            )
        )
    try:
        dependency_inputs = package_graph_representation.dependency_inputs(
            tuple(current_objects), package_graph_id
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            "PACKAGE_MIGRATION_PACKAGE_GRAPH_DEPENDENCY_COMMITMENT_INVALID"
        ) from exc
    if (
        payload["nodes_digest"] != value_digest(dependency_inputs["nodes"])
        or payload["edges_digest"] != value_digest(dependency_inputs["edges"])
    ):
        raise ValueError(
            "PACKAGE_MIGRATION_PACKAGE_GRAPH_DEPENDENCY_COMMITMENT_DIFFERS"
        )

    expected_digest = NamespaceObject.create(
        package_graph["object_id"],
        represented_kind,
        payload,
        package_graph["operands"],
    ).digest
    if type(representation_updates) is not list:
        raise ValueError("PACKAGE_MIGRATION_PACKAGE_GRAPH_REPRESENTATION_REQUIRED")
    selected = [
        update
        for update in representation_updates
        if update.get("object_id") == package_graph_id
    ]
    if len(selected) != 1:
        raise ValueError("PACKAGE_MIGRATION_PACKAGE_GRAPH_REPRESENTATION_REQUIRED")
    update = selected[0]
    evidence = update.get("evidence")
    if (
        update.get("current_object_digest") != expected_digest
        or type(evidence) is not list
        or not evidence
    ):
        raise ValueError("PACKAGE_MIGRATION_PACKAGE_GRAPH_REPRESENTATION_INVALID")

    owned = {
        surface.split(":", 2)[1]
        for surface in package_graph.get("surfaces", [])
        if type(surface) is str
        and surface.startswith(("file:", "python:"))
        and len(surface.split(":", 2)) >= 2
    }
    references_valid = all(
        type(reference) is dict
        and set(reference) == {"path", "sha256"}
        and type(reference.get("path")) is str
        and (
            (
                permit_stale_sha
                and reference["path"] in files
                and _is_sha256_digest(reference.get("sha256"))
            )
            or files.get(reference["path"]) == reference.get("sha256")
        )
        for reference in evidence
    )
    if not references_valid or not any(
        reference["path"] in owned for reference in evidence
    ):
        raise ValueError(
            "PACKAGE_MIGRATION_PACKAGE_GRAPH_REPRESENTATION_EVIDENCE_INVALID"
        )


def _retire_package_graph_instance_check(
    namespace: dict,
    registry: dict[str, namespace_contracts.KindContract],
    package_graph_id: str,
    representation_updates: list[dict],
    files: dict[str, str],
) -> list[dict]:
    """Retire only the package root's superseded retained GRAPH-3.1 selection.

    The fresh package adapter derives the registered four-field graph-statics
    layout from the complete current object collection.  It does not supersede
    GRAPH-3.1 evidence for any other GRAPH or another coordinate selected for
    the package root.  Artifact files remain untouched.
    """

    _validate_package_graph_adapter_basis(
        namespace,
        registry,
        package_graph_id,
        representation_updates,
        files,
    )
    by_id = {row["object_id"]: row for row in namespace["objects"]}
    try:
        package_graph = by_id[package_graph_id]
        represented_kind = namespace_contracts.ancestors(
            registry, package_graph["kind"]
        )[-1]
    except (KeyError, TypeError) as exc:
        raise ValueError(
            "PACKAGE_MIGRATION_PACKAGE_GRAPH_RETIREMENT_UNCLASSIFIABLE"
        ) from exc
    if represented_kind != "GRAPH":
        raise ValueError(
            "PACKAGE_MIGRATION_PACKAGE_GRAPH_RETIREMENT_UNCLASSIFIABLE"
        )

    retained: list[dict] = []
    retired: list[dict] = []
    for check in namespace.get("instance_checks", []):
        if not (
            check.get("object_id") == package_graph_id
            and check.get("coordinate") == _PACKAGE_GRAPH_COORDINATE
        ):
            retained.append(deepcopy(check))
            continue
        try:
            route = current_object_routes.select_current_object_route(
                semantic_version=check["semantic_version"],
                objective=check["coordinate"],
                represented_kind=represented_kind,
            )
        except (
            KeyError,
            TypeError,
            current_object_routes.CurrentObjectRouteRefusal,
        ) as exc:
            raise ValueError(
                "PACKAGE_MIGRATION_PACKAGE_GRAPH_RETIREMENT_UNCLASSIFIABLE"
            ) from exc
        if check.get("proposition_digest") != route.module.PROPOSITION_DIGEST:
            raise ValueError("PACKAGE_MIGRATION_INSTANCE_PROPOSITION_DIFFERS")
        retired.append(deepcopy(check))
    if len(retired) > 1:
        raise ValueError("PACKAGE_MIGRATION_PACKAGE_GRAPH_SELECTION_DUPLICATED")
    namespace["instance_checks"] = retained
    return retired


def _instance_check_transition(before: dict, after: dict) -> dict:
    """Describe an exact selection transition without changing manifest bytes."""

    prior = before.get("namespace", {}).get("instance_checks", [])
    package_graph_ids = {
        row.get("object_id")
        for row in before.get("objects", [])
        if type(row) is dict and row.get("object_kind") == "GRAPH"
    }
    current_digests = {
        value_digest(check)
        for check in after.get("namespace", {}).get("instance_checks", [])
    }
    removed = []
    for check in prior:
        if value_digest(check) in current_digests:
            continue
        package_graph = (
            check.get("object_id") in package_graph_ids
            and check.get("coordinate") == _PACKAGE_GRAPH_COORDINATE
        )
        removed.append({
            "object_id": check["object_id"],
            "coordinate": check["coordinate"],
            "semantic_version": check["semantic_version"],
            "selection_digest": value_digest(check),
            "replacement_mechanism": (
                _PACKAGE_GRAPH_REPLACEMENT
                if package_graph
                else "fresh-current-package-facet-replay"
            ),
            "reason": (
                (
                    "The fresh source-bound package GRAPH adapter binds the complete "
                    "current object and collection and explicitly projects only the "
                    "registered four-field statics layout. This retires only the "
                    "package-root GRAPH-3.1 selection; it is not a generic graph "
                    "selection replacement. The historical evidence artifacts remain "
                    "on disk but are no longer an active package selection."
                )
                if package_graph
                else (
                    "The additive package VERIFIER now replays this registered "
                    "structural facet over the current object and current full package "
                    "collection. The historical evidence artifact remains on disk but "
                    "is no longer an active package selection."
                )
            ),
        })
    return {
        "prior_count": len(prior),
        "current_count": len(after.get("namespace", {}).get("instance_checks", [])),
        "replaced_count": len(removed),
        "replaced": removed,
    }


_NAMED = {
    **{
        path: ("vstd-invocation-ledger", "LEDGER", ["TRANSACTION"])
        for path in (
            "src/verifier/runtime/polish_invocation_ledger.py",
            "src/verifier/runtime/local_ledger_controls.py",
            "src/verifier/runtime/local_ledger_control_checks.py",
            "src/verifier/runtime/local_ledger_execution.py",
            "src/verifier/runtime/local_ledger_worker.py",
        )
    },
    **{
        path: ("vstd-manifest-write", "TRANSACTION", [])
        for path in (
            "src/verifier/runtime/namespace_cli.py",
            "src/verifier/runtime/manifest_write_execution.py",
            "src/verifier/runtime/manifest_write_worker.py",
        )
    },
}


def _installed_semantic_catalog_ids(
    rows: object,
    specs_by_id: dict[str, object],
    *,
    permit_stale_reason: bool = False,
) -> set[str]:
    """Return IDs that prove installation, not legacy same-ID occupancy."""

    if type(rows) is not list:
        return set()
    installed: set[str] = set()
    for row in rows:
        if type(row) is not dict:
            continue
        object_id = row.get("object_id")
        spec = specs_by_id.get(object_id)
        if spec is None:
            continue
        specializations = row.get("specializations")
        if type(specializations) is not list or any(
            type(kind) is not str for kind in specializations
        ):
            continue
        surfaces = row.get("surfaces")
        if type(surfaces) is not list or any(
            type(surface) is not str for surface in surfaces
        ):
            continue
        surface_paths: set[str] = set()
        for surface in surfaces:
            if surface.startswith("file:"):
                surface_paths.add(surface.removeprefix("file:"))
            elif ":" in surface:
                surface_paths.add(surface.split(":", 2)[1])
            else:
                surface_paths.clear()
                break
        current_payload = {"representation_role": spec.representation_role}
        prior_role = _PRE_APPLICABILITY_REPRESENTATION_ROLES.get(object_id)
        accepted_payloads = [current_payload]
        if prior_role is not None:
            accepted_payloads.append({"representation_role": prior_role})
        required_paths = set(spec.owned_paths) - set(
            _PRE_APPLICABILITY_MISSING_OWNED_PATHS.get(object_id, ())
        )
        if (
            row.get("kind") == spec.primary_kind
            and set(spec.specializations) <= set(specializations)
            and row.get("payload") in accepted_payloads
            and (
                permit_stale_reason
                or row.get("reason")
                == spec.necessity_reason
                + " Boundary: "
                + spec.consequence_boundary
            )
            and row.get("operands")
            == {role: list(targets) for role, targets in spec.operands}
            # The exact install validator later limits any extra path to a
            # catalog-pending legacy fallback. Recovery only establishes that
            # this row owns its complete source denominator; it cannot authorize
            # a missing required path.
            and required_paths <= surface_paths
        ):
            installed.add(object_id)
    return installed

# The language extension is a closed package boundary.  Enumerating every
# current file here makes a new or omitted worker a review event instead of
# letting an ``extensions/languages`` prefix silently widen HARNESS ownership.
_HARNESS_LANGUAGE_PATHS = (
    "extensions/languages/pyproject.toml",
    "extensions/languages/src/vstd_languages/__init__.py",
    "extensions/languages/src/vstd_languages/extended_batch_two.py",
    "extensions/languages/src/vstd_languages/extended_batch_three.py",
)

# This is a reviewed ownership boundary, not a filename heuristic. The base
# HARNESS object already exists in the retained 26-object package graph.
_HARNESS_PATHS = (
    "src/verifier/core/run.py",
    "src/verifier/core/run_support.py",
    "src/verifier/core/run_planning.py",
    "src/verifier/core/run_validation.py",
    "src/verifier/core/run_inspection.py",
    "src/verifier/core/run_reproduction.py",
    "src/verifier/core/run_impact.py",
    "src/verifier/core/run_process_observation.py",
    "src/verifier/core/owned_process.py",
    "src/verifier/runtime/language_runners.py",
    "src/verifier/runtime/package_harness_applicability.py",
    *_HARNESS_LANGUAGE_PATHS,
)

# A LEDGER refutation must cover the entire reviewed HARNESS source boundary,
# including the two retained certificate checkers that were already owned by
# HARNESS before the launch surfaces moved here.  The narrower TRANSACTION set
# names only sources that launch/relaunch subjects, publish receipts, or state
# the parent-observation limit used by those effect paths.
_HARNESS_LEDGER_REVIEW_PATHS = (
    "src/verifier/domains/harness.py",
    "src/verifier/domains/contracts/harness_checks.py",
    "src/verifier/domains/contracts/harness_gap_boundary.py",
    *_HARNESS_PATHS,
)

_HARNESS_TRANSACTION_PATHS = (
    "src/verifier/core/run.py",
    "src/verifier/core/run_reproduction.py",
    "src/verifier/core/run_process_observation.py",
    "src/verifier/core/owned_process.py",
    "src/verifier/runtime/language_runners.py",
    "extensions/languages/src/vstd_languages/__init__.py",
    "extensions/languages/src/vstd_languages/extended_batch_two.py",
    "extensions/languages/src/vstd_languages/extended_batch_three.py",
)

# These core mechanisms have narrower semantic owners in the audited ownership
# catalog.  The constants are repeated here so routing remains explicit even in
# the synthetic migration fixtures that do not activate that catalog.
_CORE_PROVENANCE_PATHS = ("src/verifier/core/provenance.py",)
_CORE_RECEIPT_PATHS = ("src/verifier/core/receipt.py",)
_CORE_EXECUTOR_PATHS = (
    "src/verifier/core/certification_mechanisms.py",
    "src/verifier/core/depth.py",
    "src/verifier/core/evidence.py",
    "src/verifier/core/grounded_certification.py",
    "src/verifier/core/profile_obligations.py",
    "src/verifier/core/translation.py",
    "src/verifier/core/witness.py",
)
# These pure modules also need a path-owned child: refuting consequence roles
# on their bytes cannot refute the broad VERIFIER catch-all that owns runtime
# and domain execution code too.  Keep the denominator explicit so new core
# source fails closed until assigned to one reviewed child.
_VERIFIER_CORE_PATHS = (
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
)
_CORE_SEMANTIC_PATHS = (
    *_CORE_EXECUTOR_PATHS,
    *_CORE_PROVENANCE_PATHS,
    *_CORE_RECEIPT_PATHS,
    *_VERIFIER_CORE_PATHS,
)

# These modules are the shipped implementations of already-retained package
# objects.  Their ownership is semantic and reviewed path-by-path: a nearby
# helper such as ``domains/common.py`` remains generic unless it receives its
# own review.  Keeping this table explicit prevents a filename heuristic from
# silently reassigning a future module or hiding a domain implementation in the
# catch-all OBJECT row.
_DOMAIN_IMPLEMENTATION_KINDS = {
    "src/verifier/domains/actor.py": "ACTOR",
    "src/verifier/domains/agent.py": "AGENT",
    "src/verifier/domains/bench.py": "BENCH",
    "src/verifier/domains/bot.py": "BOT",
    "src/verifier/domains/collective.py": "COLLECTIVE",
    "src/verifier/domains/data.py": "DATA",
    "src/verifier/domains/env.py": "ENV",
    "src/verifier/domains/hardware.py": "HARDWARE",
    "src/verifier/domains/harness.py": "HARNESS",
    "src/verifier/domains/human.py": "HUMAN",
    "src/verifier/domains/identity.py": "IDENTITY",
    "src/verifier/domains/model.py": "MODEL",
    "src/verifier/domains/owner.py": "OWNER",
    "src/verifier/domains/role.py": "ROLE",
    "src/verifier/domains/sim.py": "SIM",
    "src/verifier/domains/token.py": "TOKEN",
    "src/verifier/domains/train.py": "TRAIN",
    "src/verifier/domains/verifier.py": "VERIFIER",
    "src/verifier/domains/verifier_bootstrap.py": "VERIFIER",
}

# These domain modules retain their historical owner until the semantic catalog
# is explicitly installed.  They are intentionally excluded from the reserved
# set so an audited path-owned child can supersede the fallback without a
# duplicate-owner exception.
_SEMANTIC_DOMAIN_FALLBACK_KINDS = {
    "src/verifier/domains/verifier_execution.py": "VERIFIER",
}

_HARNESS_LEDGER_OBLIGATIONS = (
    "LEDGER-0.1-authoritative-history",
    "LEDGER-0.2-accounting-invariants",
    "LEDGER-0.3-correction-and-recovery",
)

# These exact sources already had complete reviews on broad catch-all owners
# before source-specific semantic ownership existed. Once the exact child is
# installed and independently reviewed, the old answer must be retired
# explicitly. It cannot move silently, remain on an owner that no longer owns
# the source, or become a blanket refutation of that broad owner's other files.
_REVIEW_TRANSFERS = (
    (
        "vstd-package-object",
        "vstd-dataset-provenance-policy",
        "POLICY",
        "src/verifier/data/policy.py",
    ),
    (
        "verifier-core-self",
        "vstd-package-worker-exchange",
        "PROTOCOL",
        "src/verifier/runtime/package_execution.py",
    ),
)


def _append_existing_evidence(
    target: list[dict[str, str]], references: list[dict[str, str]]
) -> None:
    """Move selected references without refreshing or inventing their bytes."""
    by_path = {reference["path"]: reference["sha256"] for reference in target}
    for reference in references:
        path, digest = reference["path"], reference["sha256"]
        if path in by_path and by_path[path] != digest:
            raise ValueError("PACKAGE_MIGRATION_HARNESS_EVIDENCE_CONFLICT")
        if path not in by_path:
            target.append(deepcopy(reference))
            by_path[path] = digest


def _rehome_unresolved_candidate_evidence(
    rows: dict[str, dict],
    previous: dict[str, dict],
    observed: dict,
    owners_by_path: dict[str, str],
) -> None:
    """Follow corrected ownership without treating movement as semantic review.

    Only unanswered classification references and blank obligation candidates
    move.  A reviewed answer remains byte-for-byte on its prior object, where
    the ordinary ownership binding check makes the required re-review visible.
    """
    surfaces_by_path: dict[str, set[str]] = {}
    for surface in observed["surfaces"]:
        if surface["path"] in owners_by_path:
            surfaces_by_path.setdefault(surface["path"], set()).add(
                surface["surface_id"]
            )
    for path, target_id in sorted(owners_by_path.items()):
        selected_surfaces = surfaces_by_path.get(path, set())
        if not selected_surfaces:
            continue
        prior_owners = [
            identifier
            for identifier, row in previous.items()
            if identifier != target_id
            and selected_surfaces.intersection(row["surfaces"])
        ]
        target = rows[target_id]
        for identifier in prior_owners:
            source = rows[identifier]
            for kind, decision in source["classification"].items():
                target_decision = target["classification"].get(kind)
                if (
                    decision is not None
                    and decision["status"] == "UNRESOLVED"
                    and target_decision is not None
                    and target_decision["status"] == "UNRESOLVED"
                ):
                    moved = [
                        reference
                        for reference in decision["evidence"]
                        if reference["path"] == path
                    ]
                    _append_existing_evidence(target_decision["evidence"], moved)
                    decision["evidence"] = [
                        reference
                        for reference in decision["evidence"]
                        if reference["path"] != path
                    ]
                for name, binding in source["obligations"].items():
                    if not name.startswith(kind + "-"):
                        continue
                    if binding.get("reason") or any(binding["declaration"].values()):
                        continue
                    moved = [
                        reference
                        for reference in binding["evidence"]
                        if reference["path"] == path
                    ]
                    if not moved:
                        continue
                    target_binding = target["obligations"].get(name)
                    if target_binding is None:
                        # A prior candidate can remain material even when current
                        # source hints no longer regenerate its obligation set.
                        # Create only the same unanswered question before moving
                        # its selected evidence; never infer applicability or an
                        # answer from ownership.
                        target_binding = deepcopy(binding)
                        target_binding["evidence"] = []
                        target["obligations"][name] = target_binding
                    if target_binding.get("reason") or any(
                        target_binding["declaration"].values()
                    ):
                        # A separately reviewed target cannot silently absorb or
                        # erase another object's still-unanswered evidence.
                        continue
                    _append_existing_evidence(target_binding["evidence"], moved)
                    binding["evidence"] = [
                        reference
                        for reference in binding["evidence"]
                        if reference["path"] != path
                    ]


def _retire_transferred_reviews(
    rows: dict[str, dict], files: dict[str, str], registry: dict
) -> None:
    """Retire old-owner answers only after the exact child is fully reviewed.

    The broad owner returns to an unanswered question because the remaining
    owned sources have not yet been reviewed as a whole. The obligation stays
    present and blank; the complete child answer carries the transferred
    source's semantics. The operation is deterministic and idempotent.
    """
    canonical = (
        "Migration retains this applicability question. Static ownership alone "
        "cannot refute a {kind} role."
    )
    draft = deepcopy(rows)
    for parent_id, child_id, kind, path in _REVIEW_TRANSFERS:
        if child_id not in draft:
            continue
        if parent_id not in draft:
            raise ValueError("PACKAGE_MIGRATION_REVIEW_TRANSFER_OBJECT_MISSING")
        parent, child = draft[parent_id], draft[child_id]
        digest = files.get(path)
        if digest is None:
            raise ValueError("PACKAGE_MIGRATION_REVIEW_TRANSFER_SOURCE_MISSING")
        parent_paths = {
            surface.removeprefix("file:")
            for surface in parent["surfaces"]
            if surface.startswith("file:")
        }
        child_paths = {
            surface.removeprefix("file:")
            for surface in child["surfaces"]
            if surface.startswith("file:")
        }
        if path in parent_paths or path not in child_paths:
            raise ValueError("PACKAGE_MIGRATION_REVIEW_TRANSFER_OWNERSHIP_DIFFERS")

        expected_obligations = {
            obligation["id"]: tuple(obligation["declaration_fields"])
            for obligation in namespace_contracts.requirements_for(registry, (kind,))
            if obligation["kind"] == kind
        }
        child_decision = child["classification"].get(kind)
        if (
            not isinstance(child_decision, dict)
            or child_decision.get("status") != "APPLIES"
            or not child_decision.get("reason", "").strip()
            or not any(
                reference.get("path") == path and reference.get("sha256") == digest
                for reference in child_decision.get("evidence", [])
            )
        ):
            raise ValueError("PACKAGE_MIGRATION_REVIEW_TRANSFER_CHILD_INCOMPLETE")
        for obligation_id, fields in expected_obligations.items():
            binding = child["obligations"].get(obligation_id)
            if (
                not isinstance(binding, dict)
                or not binding.get("reason", "").strip()
                or set(binding.get("declaration", {})) != set(fields)
                or not all(
                    isinstance(value, str) and value.strip()
                    for value in binding["declaration"].values()
                )
                or not binding.get("evidence")
                or any(
                    files.get(reference.get("path")) != reference.get("sha256")
                    or reference.get("path") not in child_paths
                    for reference in binding["evidence"]
                )
            ):
                raise ValueError(
                    "PACKAGE_MIGRATION_REVIEW_TRANSFER_CHILD_OBLIGATION_INCOMPLETE"
                )

        parent_decision = parent["classification"].get(kind)
        independently_reviewed = (
            isinstance(parent_decision, dict)
            and parent_decision.get("status") in {"APPLIES", "DOES_NOT_APPLY"}
            and bool(parent_decision.get("reason", "").strip())
            and bool(parent_decision.get("evidence"))
            and all(
                reference.get("path") in parent_paths
                and reference.get("path") != path
                and files.get(reference.get("path")) == reference.get("sha256")
                for reference in parent_decision["evidence"]
            )
        )
        if independently_reviewed:
            for obligation_id, fields in expected_obligations.items():
                binding = parent["obligations"].get(obligation_id)
                if (
                    not isinstance(binding, dict)
                    or not binding.get("reason", "").strip()
                    or set(binding.get("declaration", {})) != set(fields)
                    or not all(
                        isinstance(value, str) and value.strip()
                        for value in binding["declaration"].values()
                    )
                    or not binding.get("evidence")
                    or any(
                        reference.get("path") not in parent_paths
                        or reference.get("path") == path
                        or files.get(reference.get("path"))
                        != reference.get("sha256")
                        for reference in binding["evidence"]
                    )
                ):
                    raise ValueError(
                        "PACKAGE_MIGRATION_REVIEW_TRANSFER_PARENT_INDEPENDENT_INCOMPLETE"
                    )
            continue
        blank = (
            isinstance(parent_decision, dict)
            and parent_decision.get("status") == "UNRESOLVED"
            and parent_decision.get("reason") == canonical.format(kind=kind)
            and parent_decision.get("evidence") == []
        )
        if not blank:
            if (
                not isinstance(parent_decision, dict)
                or parent_decision.get("status") != "APPLIES"
                or not parent_decision.get("reason", "").strip()
                or parent_decision.get("evidence") != [{"path": path, "sha256": digest}]
            ):
                raise ValueError("PACKAGE_MIGRATION_REVIEW_TRANSFER_PARENT_DIFFERS")
            for obligation_id, fields in expected_obligations.items():
                binding = parent["obligations"].get(obligation_id)
                if (
                    not isinstance(binding, dict)
                    or not binding.get("reason", "").strip()
                    or set(binding.get("declaration", {})) != set(fields)
                    or not all(
                        isinstance(value, str) and value.strip()
                        for value in binding["declaration"].values()
                    )
                    or binding.get("evidence") != [{"path": path, "sha256": digest}]
                ):
                    raise ValueError(
                        "PACKAGE_MIGRATION_REVIEW_TRANSFER_PARENT_OBLIGATION_DIFFERS"
                    )
            parent_decision.update(
                status="UNRESOLVED",
                reason=canonical.format(kind=kind),
                evidence=[],
            )

        for obligation_id, fields in expected_obligations.items():
            binding = parent["obligations"].get(obligation_id)
            empty = {
                "reason": "",
                "evidence": [],
                "declaration": {field: "" for field in fields},
            }
            if blank and binding != empty:
                raise ValueError("PACKAGE_MIGRATION_REVIEW_TRANSFER_NOT_IDEMPOTENT")
            parent["obligations"][obligation_id] = empty
    rows.clear()
    rows.update(draft)


def _rehome_harness_candidate_evidence(
    rows: dict[str, dict], previous: dict[str, dict], observed: dict, harness_id: str
) -> None:
    """Compatibility wrapper for the reviewed HARNESS ownership boundary."""
    _rehome_unresolved_candidate_evidence(
        rows, previous, observed, {path: harness_id for path in _HARNESS_PATHS}
    )


def _owned_current_evidence(
    root: Path,
    row: dict,
    files: dict[str, str],
    paths: tuple[str, ...],
    error_prefix: str,
) -> list[dict[str, str]]:
    """Bind reviewed declarations to current bytes on their declared owner."""
    owned = set(row["surfaces"])
    evidence = []
    for path in paths:
        if "file:" + path not in owned:
            raise ValueError(error_prefix + "_OWNERSHIP_DIFFERS")
        try:
            digest = bytes_digest((root / path).read_bytes())
        except OSError as exc:
            raise ValueError(error_prefix + "_SOURCE_UNAVAILABLE") from exc
        if files.get(path) != digest:
            raise ValueError(error_prefix + "_SOURCE_DIFFERS")
        evidence.append({"path": path, "sha256": digest})
    return evidence


def _review_decision_conflicts(
    previous: dict, selected: dict, *, refresh_reviewed: bool
) -> bool:
    """Allow an explicit review refresh without erasing a contrary decision."""
    if previous["status"] == "UNRESOLVED" or previous == selected:
        return False
    return not (
        refresh_reviewed and previous["status"] == selected["status"]
    )


def _review_binding_conflicts(
    previous: dict | None, selected: dict, *, refresh_reviewed: bool
) -> bool:
    """Replace only the exact binding selected for a requested review refresh."""
    if not previous or not (
        previous["reason"] or any(previous["declaration"].values())
    ):
        return False
    return previous != selected and not refresh_reviewed


def _upsert_execution_check(
    checks: list[dict], selected: dict, *, refresh_reviewed: bool
) -> None:
    """Refresh one exact mechanism selection; duplicates remain a hard conflict."""
    indexes = [
        index
        for index, check in enumerate(checks)
        if (check["object_id"], check["mechanism"])
        == (selected["object_id"], selected["mechanism"])
    ]
    if len(indexes) > 1:
        raise ValueError("PACKAGE_MIGRATION_EXECUTION_SELECTION_CONFLICT")
    if not indexes:
        checks.append(selected)
        return
    index = indexes[0]
    if checks[index] == selected:
        return
    if not refresh_reviewed:
        raise ValueError("PACKAGE_MIGRATION_EXECUTION_SELECTION_CONFLICT")
    checks[index] = selected


def _canonical_review_selection(
    root: Path,
    row: dict,
    files: dict[str, str],
    review_module: object,
    kind: str,
    error_prefix: str,
    *,
    refresh_reviewed: bool,
) -> dict:
    """Select one role from its installed semantic review, never duplicate it.

    The source-review module owns applicability reasons, evidence denominators,
    and Tier-0 declarations.  A mechanism selector owns only the separate
    execution-check reason and evidence.  Keeping those authorities distinct
    prevents a narrower executable specimen from silently rewriting repository
    admission semantics.
    """

    review_document = review_module.review_document()
    review = review_document.get(row["object_id"])
    if type(review) is not dict or review.get("primary_kind") != row.get("kind"):
        raise ValueError(error_prefix + "_REVIEW_OWNER_DIFFERS")
    expected = review.get("classification", {}).get(kind)
    if (
        type(expected) is not dict
        or expected.get("status") not in {"APPLIES", "DOES_NOT_APPLY"}
        or type(expected.get("reason")) is not str
        or not expected["reason"].strip()
        or type(expected.get("evidence_paths")) is not list
        or any(type(path) is not str for path in expected["evidence_paths"])
        or len(expected["evidence_paths"]) != len(set(expected["evidence_paths"]))
    ):
        raise ValueError(error_prefix + "_REVIEW_INVALID")
    paths = tuple(expected["evidence_paths"])
    if row.get("object_id") == "vstd-harness":
        required_paths = {
            "LEDGER": _HARNESS_LEDGER_REVIEW_PATHS,
            "TRANSACTION": _HARNESS_TRANSACTION_PATHS,
        }.get(kind)
        if required_paths is not None and (
            len(paths) != len(required_paths) or set(paths) != set(required_paths)
        ):
            # A negative LEDGER answer is valid only over every HARNESS-owned
            # source.  TRANSACTION is narrower, but it must still cover every
            # reviewed launch, relaunch, and result-publication implementation.
            raise ValueError(error_prefix + "_EVIDENCE_DENOMINATOR_DIFFERS")
    evidence = _owned_current_evidence(root, row, files, paths, error_prefix)
    decision = {
        "status": expected["status"],
        "reason": expected["reason"],
        "evidence": evidence,
    }
    previous_decision = row["classification"].get(kind)
    if previous_decision is not None and _review_decision_conflicts(
        previous_decision, decision, refresh_reviewed=refresh_reviewed
    ):
        raise ValueError(error_prefix + "_DECISION_CONFLICT")

    declarations = {
        obligation_id: deepcopy(answers)
        for obligation_id, answers in review.get("declarations", {}).items()
        if obligation_id.startswith(kind + "-")
    }
    if decision["status"] == "APPLIES" and not declarations:
        raise ValueError(error_prefix + "_REVIEW_INVALID")
    if decision["status"] == "DOES_NOT_APPLY" and declarations:
        raise ValueError(error_prefix + "_REVIEW_INVALID")

    bindings: dict[str, dict] = {}
    for obligation_id, answers in declarations.items():
        selected = {
            "reason": (
                decision["reason"]
                + " This Tier-0 declaration names the boundary only; mechanism "
                "execution and higher-tier semantic fulfillment remain unestablished."
            ),
            "evidence": deepcopy(evidence),
            "declaration": answers,
        }
        previous = row["obligations"].get(obligation_id)
        if (
            type(previous) is dict
            and type(previous.get("reason")) is str
            and previous["reason"].strip()
            and previous.get("evidence") == evidence
            and previous.get("declaration") == answers
        ):
            # Obligation reasons are feature-near explanations, not a second
            # declaration authority. Preserve a complete canonical binding.
            selected = deepcopy(previous)
        elif _review_binding_conflicts(
            previous, selected, refresh_reviewed=refresh_reviewed
        ):
            raise ValueError(error_prefix + "_DECLARATION_CONFLICT")
        bindings[obligation_id] = selected

    remove_obligations: list[str] = []
    if decision["status"] == "DOES_NOT_APPLY":
        for obligation_id, binding in row["obligations"].items():
            if not obligation_id.startswith(kind + "-"):
                continue
            reason = binding.get("reason") if type(binding) is dict else None
            declaration = (
                binding.get("declaration") if type(binding) is dict else None
            )
            populated = (
                type(binding) is not dict
                or type(reason) is not str
                or bool(reason.strip())
                or bool(binding.get("evidence"))
                or type(declaration) is not dict
                or any(declaration.values())
            )
            if populated and not refresh_reviewed:
                raise ValueError(error_prefix + "_DECLARATION_CONFLICT")
            remove_obligations.append(obligation_id)

    return {
        "decision": decision,
        "bindings": bindings,
        "remove_obligations": remove_obligations,
    }


def _select_harness_financial_classification(
    root: Path,
    row: dict,
    files: dict[str, str],
    *,
    refresh_reviewed: bool = False,
) -> None:
    """Apply the HARNESS financial decisions from their installed review."""

    ledger = _canonical_review_selection(
        root,
        row,
        files,
        package_namespace_review,
        "LEDGER",
        "PACKAGE_MIGRATION_HARNESS_LEDGER",
        refresh_reviewed=refresh_reviewed,
    )
    transaction = _canonical_review_selection(
        root,
        row,
        files,
        package_namespace_review,
        "TRANSACTION",
        "PACKAGE_MIGRATION_HARNESS_TRANSACTION",
        refresh_reviewed=refresh_reviewed,
    )
    if "LEDGER" in row["specializations"] or row["kind"] == "LEDGER":
        raise ValueError("PACKAGE_MIGRATION_HARNESS_LEDGER_LABEL_CONFLICT")
    row["classification"]["LEDGER"] = ledger["decision"]
    row["classification"]["TRANSACTION"] = transaction["decision"]
    for name in ledger["remove_obligations"]:
        row["obligations"].pop(name, None)
    row["obligations"].update(transaction["bindings"])
    if "TRANSACTION" not in row["specializations"]:
        row["specializations"].append("TRANSACTION")


def reviewed_declarations(identifier: str) -> dict[str, dict[str, str]]:
    """Source-reviewed answers, not execution receipts or inferred correctness."""
    if identifier == "vstd-invocation-ledger":
        return {
            "LEDGER-0.1-authoritative-history": {
                "history": "SQLite issuance rows retain each consumed invocation and exact proposal bytes.",
                "state": "ledger_meta selects ledger_id, policy_domain and current policy_epoch; issuance retains consumption.",
                "ordering": "The local AUTOINCREMENT sequence orders accepted entries; host timestamps are observations, not time truth.",
                "authority": "IssuerLedgerSelection is provisioned by the authenticated host, not decoded from candidate input.",
            },
            "LEDGER-0.2-accounting-invariants": {
                "units": "Integer invocation counts, retained-byte counts, sequences and policy epochs; no monetary units are represented.",
                "balance_rules": "Unique invocation_id consumption; MAX_INVOCATIONS and MAX_RETAINED_BYTES bound admitted state.",
                "rounding": "No rounding: integer bounds and exact proposal-byte digests are compared.",
                "sources_and_sinks": "Explicit provisioning creates the ledger; commit_issuance inserts once; policy epochs strictly advance. No deletion API is declared.",
            },
            "LEDGER-0.3-correction-and-recovery": {
                "corrections": "Advance the policy epoch to invalidate old selections; in-place correction of issuance records is not an offered operation.",
                "replay": "recheck_issuance_commit reads the same row; repeated consumption is refused.",
                "reconciliation": "Compare exact proposal, receipt, configured identity, epoch and mechanism digests with retained bytes.",
                "recovery": "Storage unavailability or uncertain commit returns UNKNOWN. Backup restoration and global uniqueness are not established.",
            },
            "TRANSACTION-0.1-effects-and-authority": {
                "effects": "Provision tables, insert one issuance, or advance the configured epoch in one local database.",
                "preconditions": "Validate host selection, exact proposal digest, epoch, uniqueness and resource bounds before commit.",
                "authorization": "Host provisioning and external issuer checks are prerequisites; this primitive does not authenticate an external authority channel.",
                "resources": "One configured local SQLite database and its journal; no network or distributed transaction.",
            },
            "TRANSACTION-0.2-commit-and-failure": {
                "commit": "BEGIN IMMEDIATE followed by COMMIT, with synchronous=FULL; construct the bounded receipt before commit.",
                "abort": "ROLLBACK the active transaction on an exception or known replay.",
                "finality": "A returned local commit receipt is not worldwide finality or public historical execution.",
                "partial_failure": "Cancellation, storage errors and uncertain commit remain UNKNOWN; the caller must recheck, not infer non-consumption.",
            },
            "TRANSACTION-0.3-retry-and-replay": {
                "duplicate_detection": "UNIQUE invocation_id plus an explicit existing-row check within the transaction.",
                "idempotency": "Repeated consumption is rejected, not issued again; read-only recheck is separate.",
                "retry_limits": "No automatic consumption retry; SQLite busy waiting is bounded by MAX_BUSY_SECONDS.",
                "replay": "Exact local row replay only, with current selection, policy epoch and mechanism binding.",
            },
        }
    if identifier == "vstd-manifest-write":
        return {
            "TRANSACTION-0.1-effects-and-authority": {
                "effects": "Template exclusive-create or explicit formatter replacement of the selected manifest file.",
                "preconditions": "Template refuses an existing target; formatter requires strict portable JSON and unchanged original bytes.",
                "authorization": "Explicit CLI invocation and local filesystem permissions; no publication or semantic admission authority.",
                "resources": "Selected manifest and same-directory unpublished temporary file.",
            },
            "TRANSACTION-0.2-commit-and-failure": {
                "commit": "Template writes through exclusive creation; formatter publishes via os.replace after a source-byte recheck.",
                "abort": "Exceptions propagate; formatter removes only its own unpublished temporary file.",
                "finality": "Filesystem publication only; no power-loss durability, cross-process lock or global atomicity guarantee is claimed.",
                "partial_failure": "Template write failure can leave a partial new file; a writer racing after the formatter recheck is not excluded by a lock.",
            },
            "TRANSACTION-0.3-retry-and-replay": {
                "duplicate_detection": "Exclusive create rejects duplicate template publication; formatting checks original bytes before replacement.",
                "idempotency": "Canonical formatting is content-idempotent; template creation is intentionally not repeated over an existing target.",
                "retry_limits": "No automatic retries or background replay.",
                "replay": "A fresh command rereads current input; prior success does not supply current admission evidence.",
            },
        }
    return {}


def _review_stage(
    name: str,
    apply: Any,
    root: str | Path,
    rows: dict[str, dict],
    files: dict[str, str],
    record_review_gaps: bool,
    review_gaps: list[dict[str, Any]] | None,
    *,
    reviewed: dict[str, tuple[str, ...]] | None = None,
    **options: Any,
) -> dict[str, dict]:
    """Run one catalog review; with gap recording, stale labels are reported, kept."""
    return package_review_stage_gaps.run_stage(
        lambda current: apply(root, current, files, **options),
        rows,
        name=name,
        record_gaps=record_review_gaps,
        report=review_gaps,
        reviewed=reviewed,
    )


def _require_reviewed_answers_survive(
    object_id: str,
    prior: dict[str, Any],
    current: dict[str, Any],
    *,
    record: bool,
    gaps: list[dict[str, Any]] | None,
) -> None:
    """Refuse to lose a reviewed answer, or with ``record`` report the lost obligations.

    A dropped classification question is structural and always refuses.  A dropped
    obligation that carried an authored reason or declaration means the ownership
    catalog no longer asks that question.  The maintainer path refuses so the
    developer decides; the polish path must still produce a receipt, so it reports
    the obligations and continues.  The authored text stays in the stored document's
    history, and the gap tells the developer exactly which answers no longer apply.
    """
    if not set(prior["classification"]) <= set(current["classification"]):
        raise ValueError(
            "PACKAGE_MIGRATION_REVIEWED_CLASSIFICATION_DROPPED:" + object_id
        )
    answered = {
        obligation_id
        for obligation_id, binding in prior["obligations"].items()
        if binding.get("reason", "").strip()
        or any(
            value.strip()
            for value in binding.get("declaration", {}).values()
            if isinstance(value, str)
        )
    }
    dropped = sorted(answered - set(current["obligations"]))
    if not dropped:
        return
    if not record:
        raise ValueError("PACKAGE_MIGRATION_REVIEWED_OBLIGATION_DROPPED:" + object_id)
    if gaps is not None:
        gaps.append(
            {
                "stage": "review_refresh",
                "object_id": object_id,
                "gap": "REVIEWED_OBLIGATIONS_DROPPED",
                "obligations": dropped,
            }
        )


def _consequence_retention_reason(object_id: str, kind: str) -> str:
    return namespace_consequences.compiled_role_reason(object_id, kind)


def _row_demands_kind_without_compiler_retention(
    row: dict[str, Any],
    kind: str,
    registry: dict[str, namespace_contracts.KindContract],
    surfaces: dict[str, dict[str, Any]],
) -> bool:
    """Recognize a current local declaration that independently demands ``kind``."""

    labels = {row["kind"], *row.get("specializations", ())}
    labels.update(
        source_kind
        for surface_id in row.get("surfaces", ())
        for source_kind in surfaces.get(surface_id, {}).get("source_kinds", ())
    )
    labels.update(
        label
        for label, decision in row.get("classification", {}).items()
        if type(decision) is dict and decision.get("status") == "APPLIES"
    )
    return any(
        label in registry
        and kind in namespace_contracts.ancestors(registry, label)
        for label in labels
    )


def _current_owned_refutation(
    row: dict[str, Any],
    kind: str,
    files: dict[str, str],
    surface_paths: dict[str, str],
) -> bool:
    """Admit only a fresh, source-owned independent non-applicability review."""

    decision = row.get("classification", {}).get(kind)
    if type(decision) is not dict or decision.get("status") != "DOES_NOT_APPLY":
        return False
    from verifier.runtime.namespace_classification import binding_status

    owned_paths = {
        surface_paths[surface_id]
        for surface_id in row.get("surfaces", ())
        if surface_id in surface_paths
    }
    status, _ = binding_status(decision, files, owned_paths)
    return status == "PASS"


def _retire_compiled_consequence_kind(
    row: dict[str, Any],
    kind: str,
    registry: dict[str, namespace_contracts.KindContract],
) -> None:
    """Remove only artifacts created by the retired compiler-owned role."""

    row["specializations"] = [
        label for label in row["specializations"] if label != kind
    ]
    for obligation in namespace_contracts.requirements_for(registry, (kind,)):
        if obligation["kind"] == kind:
            row["obligations"].pop(obligation["id"], None)


def _apply_required_consequence_kinds(
    rows: dict[str, dict[str, Any]],
    previous: dict[str, dict[str, Any]],
    observed: dict[str, Any],
    registry: dict[str, namespace_contracts.KindContract],
    required_kinds: dict[str, list[str]],
) -> None:
    """Compile graph-required additive roles without claiming their obligations pass.

    Local source reviews answer what one owned surface establishes in isolation.
    The selected consequence graph answers the stronger whole-graph question, so
    its additive role must supersede a local denial.  A role compiled by this
    stage is retained on later refreshes even after it enters the demanded set.
    The narrow exception is a current, source-owned independent refutation after
    the graph no longer requires the role; retaining the compiler marker there
    would make its own prior output override the new review forever.

    The compiler creates only blank obligation bindings.  Their concrete
    declarations, evidence, and realization remain open for ``reasons.vstd`` and
    the applicable higher-tier checkers.
    """

    selected = {
        object_id: set(kinds)
        for object_id, kinds in required_kinds.items()
    }
    surface_rows = {
        surface["surface_id"]: surface
        for surface in observed.get("surfaces", ())
        if type(surface) is dict
        and type(surface.get("surface_id")) is str
        and type(surface.get("path")) is str
    }
    surfaces = {
        surface_id: surface["path"]
        for surface_id, surface in surface_rows.items()
    }
    files = {
        file_row["path"]: file_row["sha256"]
        for file_row in observed.get("census", {}).get("files", ())
        if type(file_row) is dict
        and type(file_row.get("path")) is str
        and type(file_row.get("sha256")) is str
    }
    for object_id, prior in previous.items():
        classifications = prior.get("classification", {})
        if type(classifications) is not dict:
            continue
        for kind, decision in classifications.items():
            if (
                type(decision) is dict
                and decision.get("status") == "APPLIES"
                and decision.get("reason")
                == _consequence_retention_reason(object_id, kind)
            ):
                row = rows.get(object_id)
                if (
                    row is not None
                    and kind not in selected.get(object_id, set())
                    and _current_owned_refutation(row, kind, files, surfaces)
                    and not _row_demands_kind_without_compiler_retention(
                        row, kind, registry, surface_rows
                    )
                ):
                    _retire_compiled_consequence_kind(row, kind, registry)
                    continue
                selected.setdefault(object_id, set()).add(kind)

    if not selected:
        return

    for object_id in sorted(selected):
        row = rows.get(object_id)
        if row is None:
            raise ValueError(
                "PACKAGE_MIGRATION_CONSEQUENCE_OBJECT_MISSING:" + object_id
            )
        owned_paths = sorted(
            {
                surfaces[surface_id]
                for surface_id in row.get("surfaces", ())
                if surface_id in surfaces and surfaces[surface_id] in files
            }
        )
        if not owned_paths:
            raise ValueError(
                "PACKAGE_MIGRATION_CONSEQUENCE_EVIDENCE_MISSING:" + object_id
            )
        evidence = [
            {"path": path, "sha256": files[path]}
            for path in owned_paths
        ]

        for kind in sorted(selected[object_id]):
            contract = registry.get(kind)
            if contract is None:
                raise ValueError(
                    "PACKAGE_MIGRATION_CONSEQUENCE_KIND_UNREGISTERED:"
                    + object_id
                    + ":"
                    + kind
                )
            if kind != row["kind"]:
                if contract.extends is None or not namespace_contracts.compatible_specialization(
                    registry, row["kind"], kind
                ):
                    raise ValueError(
                        "PACKAGE_MIGRATION_CONSEQUENCE_KIND_NOT_SPECIALIZATION:"
                        + object_id
                        + ":"
                        + kind
                    )
                if kind not in row["specializations"]:
                    row["specializations"].append(kind)

            existing_decision = row["classification"].get(kind)
            if not (
                type(existing_decision) is dict
                and existing_decision.get("status") == "APPLIES"
                and existing_decision.get("reason")
                != _consequence_retention_reason(object_id, kind)
            ):
                row["classification"][kind] = {
                    "status": "APPLIES",
                    "reason": _consequence_retention_reason(object_id, kind),
                    "evidence": deepcopy(evidence),
                }
            for obligation in namespace_contracts.requirements_for(
                registry, (kind,)
            ):
                if obligation["kind"] != kind:
                    continue
                fields = tuple(obligation["declaration_fields"])
                existing = row["obligations"].get(obligation["id"])
                if existing is None:
                    prior_binding = previous.get(object_id, {}).get(
                        "obligations", {}
                    ).get(obligation["id"])
                    if prior_binding is not None:
                        if (
                            type(prior_binding) is not dict
                            or set(prior_binding.get("declaration", {}))
                            != set(fields)
                        ):
                            raise ValueError(
                                "PACKAGE_MIGRATION_CONSEQUENCE_OBLIGATION_CONFLICT:"
                                + object_id
                                + ":"
                                + obligation["id"]
                            )
                        row["obligations"][obligation["id"]] = deepcopy(
                            prior_binding
                        )
                    else:
                        row["obligations"][obligation["id"]] = {
                            "reason": "",
                            "evidence": [],
                            "declaration": {field: "" for field in fields},
                        }
                    continue
                if (
                    type(existing) is not dict
                    or set(existing.get("declaration", {})) != set(fields)
                ):
                    raise ValueError(
                        "PACKAGE_MIGRATION_CONSEQUENCE_OBLIGATION_CONFLICT:"
                        + object_id
                        + ":"
                        + obligation["id"]
                    )


def _documented_applies_keys(root: Path) -> frozenset[tuple[str, str]]:
    """Return exact checked root-ledger APPLIES coordinates for migration."""

    from verifier.runtime.tier_zero_reasoning import integration as reason_integration

    if not (root / "reasons.vstd").is_file():
        return frozenset()
    selection = reason_integration.select_root_reasons(root)
    return frozenset(
        (decision["object_id"], decision["object_kind"])
        for decision in selection.classification_decisions
        if decision.get("decision") == "APPLIES"
        and decision.get("object_kind")
        in package_original_kind_catalog.ORIGINAL_NON_OBJECT_KINDS
    )


def _apply_documented_obligation_bindings(
    root: Path,
    rows: dict[str, dict[str, Any]],
    observed: dict[str, Any],
    registry: dict[str, namespace_contracts.KindContract],
) -> None:
    """Compile checked demand-only reasons into source-bound Tier-0 bindings.

    ``reasons.vstd`` is the sole authored authority for conservative APPLIES
    decisions.  Those decisions retain an obligation without changing the
    compiled source-role cell or adding a specialization label.  The resulting
    declarations deliberately keep the concrete mechanism and semantic
    fulfillment ``NOT_ESTABLISHED``; they establish only that every required
    Tier-0 field has an explicit, current-source-bound repository answer.

    Compiler-selected APPLIES roles can also arrive with the canonical blank
    candidate installed by ``_apply_required_consequence_kinds``.  Fill those
    candidates under the same bounded claim instead of leaving a required row
    structurally unanswered.
    """

    from verifier.runtime.tier_zero_reasoning import integration as reason_integration

    selection = reason_integration.select_root_reasons(root)
    documented = reason_integration.documented_applicability_answers(
        selection, list(rows.values())
    )
    selected: dict[tuple[str, str], dict[str, str]] = {}
    for answer in documented:
        object_id = answer.get("object_id")
        kind = answer.get("object_kind")
        reason_id = answer.get("reason_id")
        if (
            type(object_id) is not str
            or type(kind) is not str
            or type(reason_id) is not str
            or not reason_id
            or answer.get("decision") != "APPLIES"
            or object_id not in rows
            or kind not in registry
        ):
            raise ValueError("PACKAGE_MIGRATION_DOCUMENTED_APPLICABILITY_INVALID")
        selected[object_id, kind] = {"reason_id": reason_id}

    # A graph/compiler-selected APPLIES role is independently necessary even
    # when the sole reason ledger has no open-cell answer for it.  Its blank
    # candidate is therefore materialized from the compiled decision itself.
    for object_id, row in rows.items():
        classifications = row.get("classification", {})
        if type(classifications) is not dict:
            raise ValueError(
                "PACKAGE_MIGRATION_DOCUMENTED_CLASSIFICATION_INVALID:" + object_id
            )
        for kind, decision in classifications.items():
            if (
                kind in registry
                and type(decision) is dict
                and decision.get("status") == "APPLIES"
            ):
                selected.setdefault((object_id, kind), {})

    surface_paths = {
        surface["surface_id"]: surface["path"]
        for surface in observed.get("surfaces", ())
        if type(surface) is dict
        and type(surface.get("surface_id")) is str
        and type(surface.get("path")) is str
    }
    files = {
        item["path"]: item["sha256"]
        for item in observed.get("census", {}).get("files", ())
        if type(item) is dict
        and type(item.get("path")) is str
        and type(item.get("sha256")) is str
    }

    for object_id, kind in sorted(selected):
        row = rows[object_id]
        owned_paths = sorted(
            {
                surface_paths[surface_id]
                for surface_id in row.get("surfaces", ())
                if surface_id in surface_paths and surface_paths[surface_id] in files
            },
            key=lambda path: (len(path.encode("utf-8")), path),
        )
        if not owned_paths:
            raise ValueError(
                "PACKAGE_MIGRATION_DOCUMENTED_OBLIGATION_EVIDENCE_MISSING:"
                + object_id
                + ":"
                + kind
            )
        # This binding declares only that the obligation remains required while
        # fulfillment is NOT_ESTABLISHED.  Admission requires one current file
        # owned by the object for that bounded statement; repeating every owned
        # path in every retained obligation adds no claim and can exhaust the
        # package envelope.  The selected source-semantic profile independently
        # binds the complete reviewed source denominator.
        evidence = [
            {"path": owned_paths[0], "sha256": files[owned_paths[0]]}
        ]
        obligations = row.get("obligations")
        if type(obligations) is not dict:
            raise ValueError(
                "PACKAGE_MIGRATION_DOCUMENTED_OBLIGATIONS_INVALID:" + object_id
            )
        for obligation in namespace_contracts.requirements_for(registry, (kind,)):
            if obligation["kind"] != kind:
                continue
            obligation_id = obligation["id"]
            fields = tuple(obligation["declaration_fields"])
            existing = obligations.get(obligation_id)
            if existing is not None:
                if type(existing) is not dict or set(existing) != {
                    "reason",
                    "evidence",
                    "declaration",
                }:
                    raise ValueError(
                        "PACKAGE_MIGRATION_DOCUMENTED_OBLIGATION_CONFLICT:"
                        + object_id
                        + ":"
                        + obligation_id
                    )
                declaration = existing["declaration"]
                if type(declaration) is not dict or set(declaration) != set(fields):
                    raise ValueError(
                        "PACKAGE_MIGRATION_DOCUMENTED_OBLIGATION_CONFLICT:"
                        + object_id
                        + ":"
                        + obligation_id
                    )
                complete = (
                    type(existing["reason"]) is str
                    and bool(existing["reason"].strip())
                    and type(existing["evidence"]) is list
                    and bool(existing["evidence"])
                    and all(
                        type(value) is str and bool(value.strip())
                        for value in declaration.values()
                    )
                )
                generated_not_established = (
                    all(value == "NOT_ESTABLISHED" for value in declaration.values())
                    and (
                        existing["reason"]
                        == "objects.vstd APPLIES; fulfillment NOT_ESTABLISHED."
                        or (
                            existing["reason"].startswith("reasons.vstd:")
                            and existing["reason"].endswith(
                                "; fulfillment NOT_ESTABLISHED."
                            )
                        )
                    )
                )
                blank = (
                    existing["reason"] == ""
                    and existing["evidence"] == []
                    and all(value == "" for value in declaration.values())
                )
                # These bounded NOT_ESTABLISHED rows are compiler output, not
                # independently fulfilled obligation evidence.  Re-materialize
                # them on every refresh so a changed reasons.vstd or owned
                # source byte cannot leave an otherwise complete-looking stale
                # binding behind.  Preserve every independently completed row.
                if complete and not generated_not_established:
                    continue
                if not (blank or generated_not_established):
                    raise ValueError(
                        "PACKAGE_MIGRATION_DOCUMENTED_OBLIGATION_CONFLICT:"
                        + object_id
                        + ":"
                        + obligation_id
                    )
            obligations[obligation_id] = {
                "reason": (
                    (
                        "reasons.vstd:"
                        + selected[object_id, kind]["reason_id"]
                        if "reason_id" in selected[object_id, kind]
                        else "objects.vstd APPLIES"
                    )
                    + "; fulfillment NOT_ESTABLISHED."
                ),
                "evidence": deepcopy(evidence),
                "declaration": {
                    field: "NOT_ESTABLISHED"
                    for field in fields
                },
            }


def _compiled_classification_reason(status: str, reason: str) -> str:
    """Compatibility alias for the shared compiled classification projection."""

    return namespace_consequences.compiled_classification_reason(status, reason)


def _compact_compiled_classification_reasons(
    rows: dict[str, dict[str, Any]],
) -> None:
    """Keep compiled review meaning and identity without repeated long prose.

    The exact human rationale remains in the pinned source review that produced
    the decision.  The registry retains a readable prefix and the exact digest
    of any unusually long decided rationale.  Generic open questions carry only
    their already-explicit epistemic state.  This is a compiled representation
    change: it does not alter status, evidence, refutation, applicability, or an
    obligation binding.
    """

    for object_id, row in rows.items():
        classifications = row.get("classification")
        if type(classifications) is not dict:
            raise ValueError(
                "PACKAGE_MIGRATION_COMPILED_CLASSIFICATION_INVALID:" + object_id
            )
        for kind, decision in classifications.items():
            if type(decision) is not dict or type(decision.get("reason")) is not str:
                raise ValueError(
                    "PACKAGE_MIGRATION_COMPILED_CLASSIFICATION_INVALID:"
                    + object_id
                    + ":"
                    + str(kind)
                )
            decision["reason"] = _compiled_classification_reason(
                decision.get("status"), decision["reason"]
            )


def _prepare_local_reviews_without_compiled_consequences(
    rows: dict[str, dict[str, Any]],
    previous: dict[str, dict[str, Any]],
) -> None:
    """Hide compiler-owned roles while independent local catalogs re-evaluate.

    A local review answers only what its owned source establishes in isolation.
    A consequence role is compiled later from the complete selected graph, so
    presenting that label to a local catalog creates a false label conflict on
    the next refresh.  Remove only roles carrying this compiler's exact marker;
    ``_apply_required_consequence_kinds`` later restores the role and its prior
    obligation bindings unless the current graph no longer requires it and a
    fresh source-owned independent review refutes it.
    """

    for object_id, prior in previous.items():
        row = rows.get(object_id)
        if row is None:
            continue
        classifications = prior.get("classification", {})
        if type(classifications) is not dict:
            continue
        for kind, decision in classifications.items():
            if (
                type(decision) is not dict
                or decision.get("status") != "APPLIES"
                or decision.get("reason")
                != _consequence_retention_reason(object_id, kind)
            ):
                continue
            if row["kind"] == kind:
                raise ValueError(
                    "PACKAGE_MIGRATION_CONSEQUENCE_PRIMARY_REVIEW_CONFLICT:"
                    + object_id
                    + ":"
                    + kind
                )
            row["specializations"] = [
                label for label in row["specializations"] if label != kind
            ]
            row["classification"][kind] = {
                "status": "UNRESOLVED",
                "reason": (
                    "Migration retains this applicability question. Static "
                    "ownership alone cannot refute a " + kind + " role."
                ),
                "evidence": [],
            }
            for obligation_id in [
                obligation_id
                for obligation_id in row["obligations"]
                if obligation_id.split("-", 1)[0] == kind
            ]:
                del row["obligations"][obligation_id]


def _owner_for_path(
    path: str, by_kind: dict[str, str], semantic_owners: dict[str, str] | None = None
) -> str:
    """Select one reviewed package object without guessing semantic roles."""
    if path in _HARNESS_PATHS:
        return by_kind["HARNESS"]
    if path in _CORE_SEMANTIC_PATHS:
        if semantic_owners is not None and path in semantic_owners:
            return semantic_owners[path]
        # Before the semantic catalog is explicitly installed, retain the old
        # VERIFIER owner instead of silently demoting audited core source to OBJECT.
        return by_kind["VERIFIER"]
    if path in _NAMED:
        legacy_owner = _NAMED[path][0]
        semantic_owner = (
            semantic_owners.get(path) if semantic_owners is not None else None
        )
        if semantic_owner is not None and semantic_owner != legacy_owner:
            raise ValueError("PACKAGE_MIGRATION_SEMANTIC_OWNERSHIP_RESERVED_PATH")
        # A semantic catalog may take over an established named group only
        # under the same stable object ID.  With no installed catalog, the
        # legacy route remains the exact backward-compatible fallback.
        return semantic_owner or legacy_owner
    if semantic_owners is not None and path in semantic_owners:
        return semantic_owners[path]
    fallback_kind = _SEMANTIC_DOMAIN_FALLBACK_KINDS.get(path)
    if fallback_kind is not None:
        return by_kind[fallback_kind]
    implementation_kind = _DOMAIN_IMPLEMENTATION_KINDS.get(path)
    if implementation_kind is not None:
        return by_kind[implementation_kind]
    if path.startswith("src/verifier/domains/contracts/"):
        stem_kind = Path(path).stem.split("_", 1)[0].upper()
        return by_kind.get(stem_kind, by_kind["OBJECT"])
    if path.startswith("src/verifier/runtime/"):
        return by_kind["VERIFIER"]
    return by_kind["OBJECT"]


def _semantic_owner_index(semantic_specs: tuple) -> dict[str, str]:
    """Index only uniquely owned paths; duplicate catalog claims are invalid."""
    owners: dict[str, str] = {}
    for spec in semantic_specs:
        for path in spec.owned_paths:
            if path in owners:
                raise ValueError(
                    "PACKAGE_MIGRATION_SEMANTIC_OWNERSHIP_PATH_AMBIGUOUS"
                )
            owners[path] = spec.object_id
    return owners


def _require_unique_semantic_execution_owner(
    implementation: str,
    owner: str,
    rows: dict[str, dict],
) -> dict:
    """Require the catalog owner to be the sole current owner of source bytes."""
    if owner not in rows:
        raise ValueError("PACKAGE_MIGRATION_EXECUTION_SEMANTIC_OWNER_INVALID")
    surface = "file:" + implementation
    actual = [
        identifier
        for identifier, row in rows.items()
        if surface in row.get("surfaces", [])
    ]
    if len(actual) > 1:
        raise ValueError("PACKAGE_MIGRATION_EXECUTION_SEMANTIC_OWNER_AMBIGUOUS")
    if actual != [owner]:
        raise ValueError("PACKAGE_MIGRATION_EXECUTION_SEMANTIC_OWNER_INVALID")
    return rows[owner]


def _rehome_execution_checks(
    namespace: dict,
    rows: dict[str, dict],
    semantic_owners: dict[str, str],
) -> None:
    """Move a retained selection only with an exact implementation binding.

    Source ownership changed, not the selected mechanism or its evidence.  The
    retained record therefore keeps every field byte-for-byte except the object
    identifier needed to follow the uniquely owned implementation surface.
    """
    from verifier.runtime import package_execution

    seen: set[tuple[str, str]] = set()
    for check in namespace.get("execution_checks", []):
        if (
            type(check) is not dict
            or type(check.get("object_id")) is not str
            or type(check.get("mechanism")) is not str
        ):
            raise ValueError("PACKAGE_MIGRATION_EXECUTION_SELECTION_INVALID")
        if check["object_id"] not in rows:
            raise ValueError("PACKAGE_MIGRATION_EXECUTION_OBJECT_INVALID")
        try:
            implementation = package_execution.implementation(check["mechanism"])
        except ValueError as exc:
            raise ValueError(
                "PACKAGE_MIGRATION_EXECUTION_SELECTION_INVALID"
            ) from exc
        owner = semantic_owners.get(implementation)
        if owner is not None:
            _require_unique_semantic_execution_owner(implementation, owner, rows)
            evidence = check.get("evidence")
            selected_references = (
                [
                    reference
                    for reference in evidence
                    if type(reference) is dict
                    and reference.get("path") == implementation
                ]
                if type(evidence) is list
                else []
            )
            if len(selected_references) != 1:
                raise ValueError(
                    "PACKAGE_MIGRATION_EXECUTION_EVIDENCE_DOES_NOT_BIND_IMPLEMENTATION"
                )
            check["object_id"] = owner
        key = check["object_id"], check["mechanism"]
        if key in seen:
            raise ValueError(
                "PACKAGE_MIGRATION_EXECUTION_SEMANTIC_OWNER_CONFLICT"
            )
        seen.add(key)


def _execution_owner_row(
    rows: dict[str, dict],
    semantic_owners: dict[str, str],
    *,
    semantic_active: bool,
    mechanism: str,
    fallback_owner: str,
) -> dict:
    """Select the exact source owner for a newly requested execution check."""
    if not semantic_active:
        return rows[fallback_owner]
    from verifier.runtime import package_execution

    implementation = package_execution.implementation(mechanism)
    owner = semantic_owners.get(implementation, fallback_owner)
    return _require_unique_semantic_execution_owner(implementation, owner, rows)


def _validate_core_ownership_denominator(files: set[str]) -> None:
    """Refuse an unreviewed addition or removal under the real core package."""
    actual = {path for path in files if path.startswith("src/verifier/core/")}
    # Synthetic migration tests can select only the separately reviewed HARNESS
    # subset. Presence of any VERIFIER-core member activates the exact census.
    if not actual.intersection(_CORE_SEMANTIC_PATHS):
        return
    expected = (
        set(_VERIFIER_CORE_PATHS)
        | {path for path in _HARNESS_PATHS if path.startswith("src/verifier/core/")}
        | set(_CORE_SEMANTIC_PATHS)
    )
    if actual != expected:
        raise ValueError("PACKAGE_MIGRATION_CORE_OWNERSHIP_DENOMINATOR_DIFFERS")


def _validate_harness_language_ownership_denominator(files: set[str]) -> None:
    """Refuse an incomplete or widened installed language-worker boundary."""
    actual = {
        path for path in files if path.startswith("extensions/languages/")
    }
    # Synthetic migrations that do not install this optional extension do not
    # activate its denominator.  Once any member is present, all and only the
    # reviewed package files are required.
    if actual and actual != set(_HARNESS_LANGUAGE_PATHS):
        raise ValueError(
            "PACKAGE_MIGRATION_HARNESS_LANGUAGE_OWNERSHIP_DENOMINATOR_DIFFERS"
        )


def _refreshed_representation_updates(
    document: dict,
    retained: dict,
    rows: dict[str, dict],
    registry: dict,
    files: dict[str, str],
    *,
    select_harness_launch_profile: bool,
) -> list[dict]:
    """Refresh every selected current representation at current exact bytes.

    Version 4 retains the original object and separately binds the selected
    current representation. Adding a graph member changes that representation
    digest even when its payload is unchanged. The existing reason and source
    selection remain authoritative only while every selected reference is still
    present in the current census at the recorded digest.
    """
    retained_objects = {
        item.object_id: item
        for item in tier_zero_manifest._namespace_objects(retained["objects"])
    }
    updates = deepcopy(document["representation_updates"])
    graph = next(item for item in retained_objects.values() if item.kind.value == "GRAPH")
    selected = [
        update for update in updates if update.get("object_id") == graph.object_id
    ]
    if len(selected) != 1:
        raise ValueError("PACKAGE_MIGRATION_GRAPH_REPRESENTATION_REQUIRED")
    harness_id = next(
        identifier
        for identifier, item in retained_objects.items()
        if item.kind.value == "HARNESS"
    )
    selected_harness = [
        update for update in updates if update.get("object_id") == harness_id
    ]
    if select_harness_launch_profile and not selected_harness:
        launch_paths = sorted({
            launch["path"]
            for launch in rows[harness_id]["payload"]
                ["direct_launch_denominator"]["launches"]
        })
        if any(path not in files for path in launch_paths):
            raise ValueError("PACKAGE_MIGRATION_HARNESS_REPRESENTATION_EVIDENCE_DIFFERS")
        updates.append({
            "object_id": harness_id,
            "retained_object_digest": retained_objects[harness_id].digest,
            "current_object_digest": retained_objects[harness_id].digest,
            "reason": (
                "The current HARNESS representation binds the reviewed direct-launch "
                "denominator, its reasons and unobserved gaps, exact launch identities, "
                "call ASTs, whole-source canonical ASTs and current source bytes. This "
                "does not establish reachability, runtime effects, confinement or full "
                "HARNESS conformance."
            ),
            "evidence": [
                {"path": path, "sha256": files[path]} for path in launch_paths
            ],
        })
    elif select_harness_launch_profile and len(selected_harness) != 1:
        raise ValueError("PACKAGE_MIGRATION_HARNESS_REPRESENTATION_REQUIRED")

    for update in updates:
        identifier = update.get("object_id")
        if identifier not in rows or identifier not in retained_objects:
            raise ValueError("PACKAGE_MIGRATION_REPRESENTATION_OBJECT_INVALID")
        for reference in update.get("evidence", []):
            path = reference.get("path")
            if path not in files:
                raise ValueError("PACKAGE_MIGRATION_REPRESENTATION_EVIDENCE_DIFFERS")
            reference["sha256"] = files[path]
        row = rows[identifier]
        payload = deepcopy(row["payload"])
        base = namespace_contracts.ancestors(registry, row["kind"])[-1]
        if base == "GRAPH":
            payload["element_kind"] = namespace_contracts.ancestors(
                registry, payload["element_kind"]
            )[-1]
        update["retained_object_digest"] = retained_objects[identifier].digest
        update["current_object_digest"] = NamespaceObject.create(
            row["object_id"], base, payload, row["operands"]
        ).digest
    return updates


def _harness_launch_calls(declarations: object) -> dict[str, str] | None:
    """Project the unique reviewed launch/call identity denominator."""

    if not isinstance(declarations, (list, tuple)):
        return None
    calls: dict[str, str] = {}
    for row in declarations:
        if not isinstance(row, dict):
            return None
        launch_id = row.get("launch_id")
        call_sha256 = row.get("call_sha256")
        if (
            type(launch_id) is not str
            or type(call_sha256) is not str
            or launch_id in calls
        ):
            return None
        calls[launch_id] = call_sha256
    return calls


def _is_exact_harness_review_transition(
    prior: object,
    catalog: object,
    discovery: object,
) -> bool:
    """Recognize only the installed four-coordinate HARNESS review advance."""

    prior_calls = _harness_launch_calls(prior)
    catalog_calls = _harness_launch_calls(catalog)
    observed_calls = _harness_launch_calls(
        discovery.get("launches") if type(discovery) is dict else None
    )
    return (
        type(discovery) is dict
        and discovery.get("status") == "PASS"
        and type(discovery.get("launches")) is list
        and prior_calls is not None
        and prior_calls == catalog_calls == observed_calls
        and _harness_review_semantics(prior) == _harness_review_semantics(catalog)
        and value_digest(prior) == _PACKAGE_HARNESS_REVIEW_TRANSITION["prior"]
        and value_digest(catalog) == _PACKAGE_HARNESS_REVIEW_TRANSITION["catalog"]
        and value_digest(discovery["launches"])
        == _PACKAGE_HARNESS_REVIEW_TRANSITION["observed"]
    )


def _harness_review_semantics(declarations: object) -> list[dict]:
    """Exclude only source-location bindings from one reviewed launch profile."""

    if not isinstance(declarations, (list, tuple)):
        return []
    excluded = {
        "line",
        "source_sha256",
        "source_ast_sha256",
        "container_sha256",
    }
    return [
        {key: deepcopy(value) for key, value in row.items() if key not in excluded}
        for row in declarations
        if isinstance(row, dict)
    ]


def _is_exact_harness_identity_transition(
    prior: object,
    catalog: object,
    discovery: object,
) -> bool:
    """Recognize only the reviewed workflow run-to-Popen replacement."""

    if (
        not isinstance(prior, (list, tuple))
        or not isinstance(catalog, (list, tuple))
        or type(discovery) is not dict
        or discovery.get("status") != "PASS"
        or type(discovery.get("launches")) is not list
    ):
        return False
    observed = discovery["launches"]
    collections = (prior, catalog, observed)
    indexes: list[dict[str, dict]] = []
    for rows in collections:
        index: dict[str, dict] = {}
        for row in rows:
            if type(row) is not dict or type(row.get("launch_id")) is not str:
                return False
            if row["launch_id"] in index:
                return False
            index[row["launch_id"]] = row
        indexes.append(index)
    prior_by_id, catalog_by_id, observed_by_id = indexes
    old_id = _PACKAGE_HARNESS_IDENTITY_REPLACEMENT["prior"]
    new_id = _PACKAGE_HARNESS_IDENTITY_REPLACEMENT["current"]
    common = set(prior_by_id) & set(catalog_by_id)
    if not (
        set(prior_by_id) - set(catalog_by_id) == {old_id}
        and set(catalog_by_id) - set(prior_by_id) == {new_id}
        and set(catalog_by_id) == set(observed_by_id)
        and all(
            prior_by_id[launch_id].get("call_sha256")
            == catalog_by_id[launch_id].get("call_sha256")
            for launch_id in common
        )
        and value_digest(list(prior))
        == _PACKAGE_HARNESS_IDENTITY_TRANSITION["prior"]
        and value_digest(list(catalog))
        == _PACKAGE_HARNESS_IDENTITY_TRANSITION["catalog"]
        and value_digest(observed)
        == _PACKAGE_HARNESS_IDENTITY_TRANSITION["observed"]
    ):
        return False
    prior_annotation = {
        key: prior_by_id[old_id].get(key)
        for key in (
            "necessity_reason",
            "observation_disposition",
            "unobserved_gaps",
        )
    }
    current_annotation = {
        key: catalog_by_id[new_id].get(key)
        for key in prior_annotation
    }
    return prior_annotation == current_annotation


_HARNESS_SCOPE_ANNOTATION = ("necessity_reason", "observation_disposition", "unobserved_gaps")
_HARNESS_SCOPE_SOURCE = ("source_sha256", "source_ast_sha256", "line", "container_sha256")


def _harness_scope_projection(row: dict) -> dict:
    """Project one launch to the identity, call AST, and reviewed annotation."""

    keys = ("launch_id", "call_sha256", *_HARNESS_SCOPE_ANNOTATION)
    return {key: deepcopy(row.get(key)) for key in keys}


def _harness_scope_pair(before: dict, after: dict) -> str:
    """Digest one changed launch as its prior projection and its reviewed successor."""

    return value_digest({
        "prior": _harness_scope_projection(before),
        "catalog": _harness_scope_projection(after),
    })


def _launch_index(rows: object) -> dict[str, dict] | None:
    """Index one launch denominator by identity; malformed or duplicate rows fail closed."""

    if not isinstance(rows, (list, tuple)):
        return None
    index: dict[str, dict] = {}
    for row in rows:
        if type(row) is not dict or type(row.get("launch_id")) is not str:
            return None
        if row["launch_id"] in index:
            return None
        index[row["launch_id"]] = row
    return index


def _is_exact_harness_scope_transition(
    prior: object,
    catalog: object,
    discovery: object,
    *,
    transition: dict[str, Any] | None = None,
) -> bool:
    """Recognize one exact installed HARNESS denominator advance.

    The predecessor, successor, and observed denominator must carry the exact
    reviewed digests.  Each removed, added, call-changed, annotation-changed, or
    source-only launch must then match its reviewed projection in exactly its
    reviewed class.  Partial, reordered, widened, forged, or future changes are
    outside this closed set and are never generalized from it.
    """

    if (
        type(discovery) is not dict
        or discovery.get("status") != "PASS"
        or type(discovery.get("launches")) is not list
    ):
        return False
    observed = discovery["launches"]
    prior_index = _launch_index(prior)
    catalog_index = _launch_index(catalog)
    observed_index = _launch_index(observed)
    spec = _PACKAGE_HARNESS_SCOPE_TRANSITION if transition is None else transition
    if (
        not isinstance(prior, (list, tuple))
        or not isinstance(catalog, (list, tuple))
        or prior_index is None
        or catalog_index is None
        or observed_index is None
        or value_digest(list(prior)) != spec["prior"]
        or value_digest(list(catalog)) != spec["catalog"]
        or value_digest(observed) != spec["observed"]
        or _harness_launch_calls(observed) != _harness_launch_calls(catalog)
    ):
        return False
    removed = sorted(set(prior_index) - set(catalog_index))
    added = sorted(set(catalog_index) - set(prior_index))
    call_changed: list[str] = []
    annotation_changed: list[str] = []
    source_only: list[str] = []
    for launch_id in sorted(set(prior_index) & set(catalog_index)):
        before, after = prior_index[launch_id], catalog_index[launch_id]
        if before.get("call_sha256") != after.get("call_sha256"):
            call_changed.append(launch_id)
        elif any(before.get(key) != after.get(key) for key in _HARNESS_SCOPE_ANNOTATION):
            annotation_changed.append(launch_id)
        elif any(before.get(key) != after.get(key) for key in _HARNESS_SCOPE_SOURCE):
            source_only.append(launch_id)
    reviewed = {
        "removed": {
            launch_id: value_digest(_harness_scope_projection(prior_index[launch_id]))
            for launch_id in removed
        },
        "added": {
            launch_id: value_digest(_harness_scope_projection(catalog_index[launch_id]))
            for launch_id in added
        },
        "call_changed": {
            launch_id: _harness_scope_pair(
                prior_index[launch_id], catalog_index[launch_id]
            )
            for launch_id in call_changed
        },
        "annotation_changed": {
            launch_id: _harness_scope_pair(
                prior_index[launch_id], catalog_index[launch_id]
            )
            for launch_id in annotation_changed
        },
        "source_only": {
            launch_id: value_digest(_harness_scope_projection(prior_index[launch_id]))
            for launch_id in source_only
        },
    }
    return all(reviewed[kind] == spec[kind] for kind in reviewed)


def _refresh_harness_launch_denominator(
    root: Path,
    row: dict,
    previous: dict | None,
    *,
    select_profile: bool,
    refresh_reviewed: bool,
    advance_reviewed: bool,
) -> None:
    """Bind current exact bytes while preserving reviewed launch semantics.

    The first explicit migration promotes the existing source-owned reviewed
    denominator into the HARNESS payload.  Later automatic migrations may
    update only exact source/container digests and diagnostic line numbers;
    changed launch identities or call ASTs remain a hard review boundary.

    A maintainer may deliberately advance that boundary only through the
    separate ``advance_reviewed`` input.  Automatic refresh recovers selection
    flags and uses ``refresh_reviewed`` internally, so those values must never
    imply authority to replace an established launch-call review.

    Each installed scope advance is bound to the exact predecessor, reviewed
    successor, and observed denominator digests, so it applies automatically
    only from that predecessor and never from any other one.
    """

    if package_harness_applicability.SELECTION_SURFACE not in row["surfaces"]:
        return
    selected = None
    prior_selected = None
    discovery = None
    exact_review_transition: dict[str, str] | None = None
    if advance_reviewed and not (select_profile and refresh_reviewed):
        raise ValueError("PACKAGE_HARNESS_ADVANCE_REQUIRES_EXPLICIT_REVIEW")
    reapply_reviewed = advance_reviewed
    if previous is not None:
        prior_selected = package_harness_applicability.declarations_from_manifest_owner(
            previous
        )
        if not reapply_reviewed:
            selected = prior_selected
    # An installed scope advance is exact and bound to the predecessor digest,
    # so polish refresh may apply it without a maintainer advance flag. Any
    # other predecessor keeps the ordinary reviewed-denominator boundary below.
    scope_applied = False
    scope_transition = None if prior_selected is None else next(
        (
            transition
            for transition in _PACKAGE_HARNESS_SCOPE_TRANSITIONS
            if value_digest(list(prior_selected)) == transition["prior"]
        ),
        None,
    )
    if scope_transition is not None:
        discovery = package_harness_applicability.discover_repository(root)
        if not _is_exact_harness_scope_transition(
            list(prior_selected),
            list(package_harness_applicability.PACKAGE_LAUNCH_DECLARATIONS),
            discovery,
            transition=scope_transition,
        ):
            raise ValueError("PACKAGE_HARNESS_SCOPE_TRANSITION_DIFFERS")
        scope_applied = True
        selected = None
        exact_review_transition = scope_transition
    if reapply_reviewed and prior_selected is not None and not scope_applied:
        prior_ids = {item["launch_id"] for item in prior_selected}
        catalog_declarations = (
            package_harness_applicability.PACKAGE_LAUNCH_DECLARATIONS
        )
        catalog_ids = {item["launch_id"] for item in catalog_declarations}
        discovery = package_harness_applicability.discover_repository(root)
        identity_transition = _is_exact_harness_identity_transition(
            list(prior_selected),
            list(catalog_declarations),
            discovery,
        )
        if prior_ids != catalog_ids and not identity_transition:
            raise ValueError("PACKAGE_HARNESS_REVIEWED_DENOMINATOR_CHANGED")
        source_transition = _is_exact_harness_review_transition(
            list(prior_selected),
            list(catalog_declarations),
            discovery,
        )
        if identity_transition:
            exact_review_transition = _PACKAGE_HARNESS_IDENTITY_TRANSITION
        elif source_transition:
            exact_review_transition = _PACKAGE_HARNESS_REVIEW_TRANSITION
        else:
            if _harness_review_semantics(prior_selected) != (
                _harness_review_semantics(catalog_declarations)
            ):
                raise ValueError("PACKAGE_HARNESS_REVIEWED_DENOMINATOR_CHANGED")
            # An ordinary re-review may refresh bytes and line locations only
            # when the source-wide AST and every direct call are unchanged.
            package_harness_applicability.refresh_source_bindings(
                root, prior_selected
            )
    if selected is None and not select_profile and not scope_applied:
        return
    baseline = (package_harness_applicability.PACKAGE_LAUNCH_DECLARATIONS
                if selected is None else selected)
    if selected is None:
        if discovery is None:
            discovery = package_harness_applicability.discover_repository(root)
        observed = {
            item["launch_id"]: item for item in discovery.get("launches", ())
        }
        catalog = {item["launch_id"]: item for item in baseline}
        if discovery.get("status") != "PASS" or set(observed) != set(catalog):
            raise ValueError("PACKAGE_HARNESS_REVIEWED_CATALOG_NOT_CURRENT")
        if exact_review_transition is None:
            for launch_id, reviewed in catalog.items():
                current = observed[launch_id]
                compared = {"source_sha256", "call_sha256"}
                if "container_sha256" in reviewed or "container_sha256" in current:
                    compared.add("container_sha256")
                if any(
                    reviewed.get(field) != current.get(field)
                    for field in compared
                ):
                    raise ValueError("PACKAGE_HARNESS_REVIEWED_CATALOG_NOT_CURRENT")
    refreshed = package_harness_applicability.refresh_source_bindings(
        root, baseline, allow_ast_bootstrap=selected is None
    )
    if (
        exact_review_transition is not None
        and value_digest(list(refreshed))
        != exact_review_transition["refreshed"]
    ):
        raise ValueError("PACKAGE_HARNESS_REVIEWED_CATALOG_NOT_CURRENT")
    row["payload"]["direct_launch_denominator"] = (
        package_harness_applicability.denominator_document(refreshed)
    )


_RETAINED_ROOT_TAKEOVER_SCHEMA = "verifier-retained-root-takeover-preview-1"
_RETAINED_ROOT_TAKEOVER_IDS = (
    "verifier-core-self",
    "vstd-data",
    "vstd-hardware",
    "vstd-package-object",
    "vstd-training",
)


def _retained_takeover_blocker(
    code: str,
    reason: str,
    **details: object,
) -> dict:
    """Return one stable, machine-readable refusal without raising on drift."""
    return {
        "code": code,
        "reason": reason,
        **{key: details[key] for key in sorted(details)},
    }


def _retained_takeover_audits() -> dict:
    """Load only the retained rows eligible for this preview-only transition."""
    from verifier.runtime.package_original_kind_catalog_retained import (
        RETAINED_ORIGINAL_KIND_AUDITS,
    )

    return {
        row.object_id: row
        for row in RETAINED_ORIGINAL_KIND_AUDITS
        if row.object_id in _RETAINED_ROOT_TAKEOVER_IDS
    }


def _retained_takeover_specs(semantic_specs: object | None) -> tuple:
    """Use the independently reviewed systems partition, never invented rows."""
    from verifier.runtime.package_semantic_ownership_domains_systems import (
        DOMAIN_SYSTEMS_OWNERSHIP_SPECS,
    )

    if semantic_specs is None:
        return tuple(DOMAIN_SYSTEMS_OWNERSHIP_SPECS)
    if (
        type(semantic_specs) not in {tuple, list}
        or tuple(semantic_specs) != tuple(DOMAIN_SYSTEMS_OWNERSHIP_SPECS)
    ):
        return ()
    return tuple(DOMAIN_SYSTEMS_OWNERSHIP_SPECS)


def _retained_takeover_fragment(spec: object) -> dict:
    """Project one immutable ownership row into JSON-only preview evidence."""
    return {
        "object_id": spec.object_id,
        "primary_kind": spec.primary_kind,
        "specializations": list(spec.specializations),
        "owned_paths": list(spec.owned_paths),
        "representation_role": spec.representation_role,
        "necessity_reason": spec.necessity_reason,
        "consequence_boundary": spec.consequence_boundary,
        "operands": {role: list(targets) for role, targets in spec.operands},
        "root_role_decisions": [
            {
                "kind": decision.kind,
                "status": decision.status,
                "reason": decision.reason,
            }
            for decision in spec.root_role_decisions
        ],
    }


def _retained_takeover_context(
    document: dict,
    root_id: str,
    semantic_specs: object | None,
) -> tuple[object | None, dict | None, tuple[dict, ...]]:
    """Select one exact audit, current row and every overlapping source fragment."""
    audit = _retained_takeover_audits().get(root_id)
    rows = (
        document.get("namespace", {}).get("objects", ())
        if type(document) is dict
        else ()
    )
    matches = [
        row
        for row in rows
        if type(row) is dict and row.get("object_id") == root_id
    ] if type(rows) is list else []
    current = matches[0] if len(matches) == 1 else None
    audit_paths = set(audit.expected_owned_paths) if audit is not None else set()
    fragments = tuple(
        sorted(
            (
                _retained_takeover_fragment(spec)
                for spec in _retained_takeover_specs(semantic_specs)
                if audit_paths.intersection(getattr(spec, "owned_paths", ()))
            ),
            key=lambda row: row["object_id"],
        )
    )
    return audit, current, fragments


def _retained_takeover_installed_declaration(root_id: str) -> dict | None:
    """Return the frozen Tier-0 root declaration, independent of the input file."""
    for item in tier_zero_manifest._namespace_objects(
        tier_zero_manifest.installed_object_declarations()
    ):
        if item.object_id == root_id:
            return item.to_dict()
    return None


def _retained_takeover_candidate(
    document: dict,
    root_id: str,
    semantic_specs: object | None,
) -> dict:
    """Build a proposed same-ID row without applying it to the package graph."""
    from verifier.runtime.package_original_kind_profiles import owned_path_set_digest

    audit, current, fragments = _retained_takeover_context(
        document, root_id, semantic_specs
    )
    installed = _retained_takeover_installed_declaration(root_id)
    fragment_paths = sorted({
        path for fragment in fragments for path in fragment["owned_paths"]
    })
    specializations = sorted({
        kind for fragment in fragments for kind in fragment["specializations"]
    })
    current = current or {}
    audit_paths = tuple(audit.expected_owned_paths) if audit is not None else ()
    audit_hashes = tuple(audit.source_sha256) if audit is not None else ()
    return {
        "retained_root_id": root_id,
        "object_id": root_id,
        "primary_kind": audit.expected_primary if audit is not None else None,
        "representation_role": (
            installed["payload"]["representation_role"]
            if installed is not None else None
        ),
        "operands": deepcopy(installed["operands"]) if installed is not None else {},
        "owned_paths": fragment_paths,
        "owned_path_set_digest": (
            owned_path_set_digest(fragment_paths) if fragment_paths else None
        ),
        "source_sha256": {
            path: digest for path, digest in zip(audit_paths, audit_hashes)
        },
        "specializations": specializations,
        # A planner cannot silently rewrite reviewed reasons or evidence. The
        # role and obligation denominator is checked separately below.
        "reason": deepcopy(current.get("reason")),
        "classification": deepcopy(current.get("classification", {})),
        "obligations": deepcopy(current.get("obligations", {})),
        "source_fragments": [deepcopy(fragment) for fragment in fragments],
    }


def _retained_takeover_binding_differences(
    prefix: str,
    retained: object,
    proposed: object,
) -> list[dict]:
    """Expose reason/declaration/evidence loss instead of one opaque inequality."""
    if type(retained) is not dict or type(proposed) is not dict:
        return [_retained_takeover_blocker(
            prefix + "_BINDINGS_DIFFER",
            "The proposed binding map is not the exact retained mapping.",
        )]
    blockers: list[dict] = []
    retained_ids = set(retained)
    proposed_ids = set(proposed)
    if retained_ids != proposed_ids:
        blockers.append(_retained_takeover_blocker(
            prefix + "_SET_DIFFERS",
            "The proposed binding identifiers do not preserve the retained denominator.",
            missing=sorted(retained_ids - proposed_ids),
            unexpected=sorted(proposed_ids - retained_ids),
        ))
    for identifier in sorted(retained_ids & proposed_ids):
        before = retained[identifier]
        after = proposed[identifier]
        if type(before) is not dict or type(after) is not dict:
            blockers.append(_retained_takeover_blocker(
                prefix + "_BINDING_DIFFERS",
                "A proposed binding is not the exact retained structured record.",
                identifier=identifier,
            ))
            continue
        for field, suffix in (
            ("reason", "_REASON_DIFFERS"),
            ("declaration", "_DECLARATION_DIFFERS"),
            ("evidence", "_EVIDENCE_DIFFERS"),
        ):
            if before.get(field) != after.get(field):
                blockers.append(_retained_takeover_blocker(
                    prefix + suffix,
                    "The proposed binding does not preserve retained " + field + ".",
                    identifier=identifier,
                ))
        omitted = {"reason", "declaration", "evidence"}
        if (
            {key: value for key, value in before.items() if key not in omitted}
            != {key: value for key, value in after.items() if key not in omitted}
        ):
            blockers.append(_retained_takeover_blocker(
                prefix + "_FIELDS_DIFFER",
                "The proposed binding changes retained fields outside reason, declaration, and evidence.",
                identifier=identifier,
            ))
    return blockers


def _retained_takeover_cycle(rows: list[dict], root_id: str, operands: dict) -> list[str]:
    """Return one deterministic cycle in the proposed operand graph, if any."""
    adjacency: dict[str, set[str]] = {}
    for row in rows:
        if type(row) is not dict or type(row.get("object_id")) is not str:
            continue
        object_id = row["object_id"]
        selected = operands if object_id == root_id else row.get("operands")
        targets: set[str] = set()
        if type(selected) is dict:
            for role, values in selected.items():
                if role == "members" and row.get("kind") == "GRAPH":
                    continue
                if type(values) is list:
                    targets.update(value for value in values if type(value) is str)
        adjacency[object_id] = targets
    state: dict[str, int] = {}
    stack: list[str] = []
    positions: dict[str, int] = {}

    def visit(node: str) -> list[str]:
        state[node] = 1
        positions[node] = len(stack)
        stack.append(node)
        for target in sorted(adjacency.get(node, ())):
            if target not in adjacency:
                continue
            if state.get(target, 0) == 0:
                found = visit(target)
                if found:
                    return found
            elif state.get(target) == 1:
                return stack[positions[target]:] + [target]
        stack.pop()
        positions.pop(node, None)
        state[node] = 2
        return []

    for node in sorted(adjacency):
        if state.get(node, 0) == 0:
            found = visit(node)
            if found:
                return found
    return []


def retained_root_takeover_blockers(
    root: Path,
    document: dict,
    candidate: object,
    *,
    semantic_specs: object | None = None,
) -> tuple[dict, ...]:
    """Validate one preview-only same-ID takeover; never mutate the manifest."""
    from verifier.runtime.package_original_kind_profiles import owned_path_set_digest

    blockers: list[dict] = []
    if type(candidate) is not dict:
        return (_retained_takeover_blocker(
            "RETAINED_ROOT_CANDIDATE_MALFORMED",
            "A takeover candidate must be an exact dictionary.",
        ),)
    try:
        canonical_bytes(candidate)
    except (TypeError, ValueError, OverflowError):
        return (_retained_takeover_blocker(
            "RETAINED_ROOT_CANDIDATE_NOT_CANONICAL_JSON",
            "A takeover candidate must contain only canonical JSON values.",
        ),)
    expected_fields = {
        "retained_root_id", "object_id", "primary_kind", "representation_role",
        "operands", "owned_paths", "owned_path_set_digest", "source_sha256",
        "specializations", "reason", "classification", "obligations",
        "source_fragments",
    }
    candidate_fields = set(candidate)
    if candidate_fields != expected_fields:
        blockers.append(_retained_takeover_blocker(
            "RETAINED_ROOT_CANDIDATE_FIELDS_DIFFER",
            "The takeover candidate fields differ from the source-bound schema.",
            missing=sorted(expected_fields - candidate_fields),
            unexpected=sorted(
                (repr(key) for key in candidate_fields - expected_fields)
            ),
        ))
    if semantic_specs is not None:
        from verifier.runtime.package_semantic_ownership_domains_systems import (
            DOMAIN_SYSTEMS_OWNERSHIP_SPECS,
        )

        if (
            type(semantic_specs) not in {tuple, list}
            or tuple(semantic_specs) != tuple(DOMAIN_SYSTEMS_OWNERSHIP_SPECS)
        ):
            blockers.append(_retained_takeover_blocker(
                "RETAINED_ROOT_SEMANTIC_CATALOG_DIFFERS",
                "A caller-supplied semantic catalog differs from current reviewed source ownership.",
            ))
    root_id = candidate.get("retained_root_id")
    if type(root_id) is not str or root_id not in _RETAINED_ROOT_TAKEOVER_IDS:
        blockers.append(_retained_takeover_blocker(
            "RETAINED_ROOT_ID_NOT_ELIGIBLE",
            "The candidate does not name one exact retained root under review.",
            observed=root_id,
        ))
        return tuple(sorted(blockers, key=canonical_bytes))
    audit, _, expected_fragments = _retained_takeover_context(
        document, root_id, semantic_specs
    )
    installed = _retained_takeover_installed_declaration(root_id)
    if audit is None or installed is None:
        blockers.append(_retained_takeover_blocker(
            "RETAINED_ROOT_AUDIT_OR_DECLARATION_MISSING",
            "The retained audit and frozen Tier-0 declaration must both exist.",
            object_id=root_id,
        ))
        return tuple(sorted(blockers, key=canonical_bytes))

    if candidate.get("object_id") != root_id:
        blockers.append(_retained_takeover_blocker(
            "RETAINED_ROOT_SAME_ID_REQUIRED",
            "A same-kind child cannot substitute for the retained root identity.",
            expected=root_id,
            observed=candidate.get("object_id"),
        ))
    if candidate.get("primary_kind") != audit.expected_primary:
        blockers.append(_retained_takeover_blocker(
            "RETAINED_ROOT_ORIGINAL_KIND_DIFFERS",
            "The proposed primary kind differs from the retained source audit.",
            expected=audit.expected_primary,
            observed=candidate.get("primary_kind"),
        ))
    expected_role = installed["payload"]["representation_role"]
    if candidate.get("representation_role") != expected_role:
        blockers.append(_retained_takeover_blocker(
            "RETAINED_ROOT_REPRESENTATION_ROLE_DIFFERS",
            "The proposed representation role differs from the frozen root declaration.",
            expected=expected_role,
            observed=candidate.get("representation_role"),
        ))
    proposed_operands = candidate.get("operands")
    if proposed_operands != installed["operands"]:
        blockers.append(_retained_takeover_blocker(
            "RETAINED_ROOT_OPERANDS_DIFFER",
            "The proposed full operand mapping differs from the retained root layout.",
            expected=installed["operands"],
            observed=proposed_operands,
        ))

    expected_paths = list(audit.expected_owned_paths)
    if owned_path_set_digest(audit.expected_owned_paths) != audit.expected_owned_path_set_digest:
        blockers.append(_retained_takeover_blocker(
            "RETAINED_AUDIT_PATH_DIGEST_INVALID",
            "The retained audit's path denominator does not match its sealed digest.",
            object_id=root_id,
        ))
    proposed_paths = candidate.get("owned_paths")
    if proposed_paths != expected_paths:
        blockers.append(_retained_takeover_blocker(
            "RETAINED_ROOT_PATHS_DIFFER",
            "The source-fragment path union does not equal the retained audit denominator.",
            expected=expected_paths,
            observed=proposed_paths,
        ))
    proposed_path_digest = None
    if type(proposed_paths) is list and proposed_paths:
        try:
            proposed_path_digest = owned_path_set_digest(proposed_paths)
        except (TypeError, ValueError):
            pass
    if (
        candidate.get("owned_path_set_digest") != proposed_path_digest
        or proposed_path_digest != audit.expected_owned_path_set_digest
    ):
        blockers.append(_retained_takeover_blocker(
            "RETAINED_ROOT_PATH_DIGEST_DIFFERS",
            "The proposed path-set digest is not both self-consistent and audit-bound.",
            audit=audit.expected_owned_path_set_digest,
            observed=candidate.get("owned_path_set_digest"),
            recomputed=proposed_path_digest,
        ))

    expected_sources = {
        path: digest
        for path, digest in zip(audit.expected_owned_paths, audit.source_sha256)
    }
    if candidate.get("source_sha256") != expected_sources:
        blockers.append(_retained_takeover_blocker(
            "RETAINED_ROOT_SOURCE_DENOMINATOR_DIFFERS",
            "The proposed source digest map differs from the retained audit.",
        ))
    try:
        resolved_root = Path(root).resolve()
    except OSError:
        resolved_root = None
        blockers.append(_retained_takeover_blocker(
            "RETAINED_ROOT_SOURCE_ROOT_UNAVAILABLE",
            "The selected repository root cannot be resolved for source rebinding.",
        ))
    for path, expected in expected_sources.items():
        if resolved_root is None:
            break
        try:
            source = (resolved_root / path).resolve()
        except OSError:
            blockers.append(_retained_takeover_blocker(
                "RETAINED_ROOT_SOURCE_UNAVAILABLE",
                "An audited source path cannot be resolved for source rebinding.",
                path=path,
            ))
            continue
        try:
            source.relative_to(resolved_root)
        except ValueError:
            blockers.append(_retained_takeover_blocker(
                "RETAINED_ROOT_SOURCE_OUTSIDE_REPOSITORY",
                "An audited source resolves outside the selected repository.",
                path=path,
            ))
            continue
        try:
            observed = bytes_digest(source.read_bytes()) if source.is_file() else None
        except OSError:
            observed = None
        if observed != expected:
            blockers.append(_retained_takeover_blocker(
                "RETAINED_ROOT_SOURCE_DRIFT",
                "Current source bytes do not match the retained review digest.",
                expected=expected,
                observed=observed,
                path=path,
            ))

    proposed_fragments = candidate.get("source_fragments")
    if type(proposed_fragments) is list:
        for fragment in proposed_fragments:
            if type(fragment) is dict and fragment.get("operands") not in ({}, None):
                blockers.append(_retained_takeover_blocker(
                    "CHILD_OPERAND_INHERITANCE_FORBIDDEN",
                    "A child source row cannot inherit the retained root's operand edges.",
                    child_object_id=fragment.get("object_id"),
                ))
    if proposed_fragments != list(expected_fragments):
        blockers.append(_retained_takeover_blocker(
            "RETAINED_ROOT_SOURCE_FRAGMENTS_DIFFER",
            "The proposed source fragments differ from current reviewed ownership rows.",
        ))
    fragment_path_owners: dict[str, list[str]] = {}
    for fragment in expected_fragments:
        for path in fragment["owned_paths"]:
            fragment_path_owners.setdefault(path, []).append(fragment["object_id"])
    overlaps = {
        path: sorted(owners)
        for path, owners in sorted(fragment_path_owners.items())
        if len(owners) != 1
    }
    if overlaps:
        blockers.append(_retained_takeover_blocker(
            "RETAINED_ROOT_SOURCE_PATH_OVERLAP",
            "A retained source path is claimed by more than one semantic fragment.",
            overlaps=overlaps,
        ))
    wrong_fragment_kinds = sorted(
        fragment["object_id"] + ":" + fragment["primary_kind"]
        for fragment in expected_fragments
        if fragment["primary_kind"] != audit.expected_primary
    )
    if wrong_fragment_kinds:
        blockers.append(_retained_takeover_blocker(
            "RETAINED_ROOT_SOURCE_FRAGMENT_KIND_DIFFERS",
            "A source fragment has no source-established same-kind takeover relation.",
            fragments=wrong_fragment_kinds,
        ))
    decision_statuses: dict[str, set[str]] = {}
    for fragment in expected_fragments:
        for decision in fragment["root_role_decisions"]:
            decision_statuses.setdefault(decision["kind"], set()).add(
                decision["status"]
            )
    conflicts = {
        kind: sorted(statuses)
        for kind, statuses in sorted(decision_statuses.items())
        if len(statuses) > 1
    }
    if conflicts:
        blockers.append(_retained_takeover_blocker(
            "RETAINED_ROOT_FRAGMENT_ROLE_DECISIONS_CONFLICT",
            "Source fragments disagree on an accumulated root-role decision.",
            conflicts=conflicts,
        ))

    namespace = document.get("namespace", {}) if type(document) is dict else {}
    rows = namespace.get("objects", ()) if type(namespace) is dict else ()
    rows = rows if type(rows) is list else []
    root_rows = [
        row for row in rows
        if type(row) is dict and row.get("object_id") == root_id
    ]
    if len(root_rows) != 1:
        blockers.append(_retained_takeover_blocker(
            "RETAINED_ROOT_MANIFEST_ROW_COUNT_DIFFERS",
            "Exactly one current namespace row must own the retained identity.",
            count=len(root_rows),
        ))
    current = root_rows[0] if len(root_rows) == 1 else None
    graph_rows = [
        row for row in rows
        if type(row) is dict and row.get("kind") == "GRAPH"
    ]
    if len(graph_rows) != 1:
        blockers.append(_retained_takeover_blocker(
            "RETAINED_ROOT_GRAPH_ROW_COUNT_DIFFERS",
            "Exactly one GRAPH row must declare package membership.",
            count=len(graph_rows),
        ))
    else:
        members = graph_rows[0].get("operands", {}).get("members", [])
        member_count = members.count(root_id) if type(members) is list else 0
        if member_count != 1:
            blockers.append(_retained_takeover_blocker(
                "RETAINED_ROOT_GRAPH_MEMBERSHIP_COUNT_DIFFERS",
                "The retained identity must occur exactly once in GRAPH membership.",
                count=member_count,
            ))

    retained_rows = document.get("objects", ()) if type(document) is dict else ()
    retained_rows = retained_rows if type(retained_rows) is list else []
    retained_matches = [
        row for row in retained_rows
        if type(row) is dict and row.get("object_id") == root_id
    ]
    if len(retained_matches) != 1:
        blockers.append(_retained_takeover_blocker(
            "RETAINED_ROOT_DECLARATION_COUNT_DIFFERS",
            "Exactly one retained Tier-0 declaration must define the root.",
            count=len(retained_matches),
        ))
    else:
        expected_retained = next(
            row for row in tier_zero_manifest.installed_object_declarations()
            if row["object_id"] == root_id
        )
        if retained_matches[0] != expected_retained:
            blockers.append(_retained_takeover_blocker(
                "RETAINED_ROOT_DECLARATION_DIFFERS",
                "The retained Tier-0 declaration differs from the installed root.",
            ))

    for path in audit.expected_owned_paths:
        surface = "file:" + path
        owners = sorted(
            row.get("object_id")
            for row in rows
            if type(row) is dict and surface in row.get("surfaces", ())
        )
        if owners != [root_id]:
            blockers.append(_retained_takeover_blocker(
                "RETAINED_ROOT_PATH_OWNER_DUPLICATED"
                if owners else "RETAINED_ROOT_PATH_OWNER_MISSING",
                "Each retained source path must have exactly one current root owner.",
                owners=owners,
                path=path,
            ))

    if current is not None:
        if current.get("kind") != audit.expected_primary:
            blockers.append(_retained_takeover_blocker(
                "RETAINED_ROOT_CURRENT_KIND_DIFFERS",
                "The current namespace row changed the audited root kind.",
                expected=audit.expected_primary,
                observed=current.get("kind"),
            ))
        if current.get("payload", {}).get("representation_role") != expected_role:
            blockers.append(_retained_takeover_blocker(
                "RETAINED_ROOT_CURRENT_REPRESENTATION_ROLE_DIFFERS",
                "The current namespace row changed the retained representation role.",
            ))
        if current.get("operands") != installed["operands"]:
            blockers.append(_retained_takeover_blocker(
                "RETAINED_ROOT_CURRENT_OPERANDS_DIFFER",
                "The current namespace row changed the retained operand layout.",
            ))
        if candidate.get("reason") != current.get("reason"):
            blockers.append(_retained_takeover_blocker(
                "RETAINED_ROOT_OBJECT_REASON_DIFFERS",
                "The proposed row does not preserve the current reviewed object reason.",
            ))
        blockers.extend(_retained_takeover_binding_differences(
            "RETAINED_ROOT_CLASSIFICATION",
            current.get("classification"),
            candidate.get("classification"),
        ))
        blockers.extend(_retained_takeover_binding_differences(
            "RETAINED_ROOT_OBLIGATION_BINDING",
            current.get("obligations"),
            candidate.get("obligations"),
        ))
        current_roles = current.get("specializations")
        proposed_roles = candidate.get("specializations")
        if current_roles != proposed_roles:
            blockers.append(_retained_takeover_blocker(
                "RETAINED_ROOT_SEMANTIC_ROLES_DIFFER",
                "The child source-role union differs from current retained root roles.",
                current=current_roles,
                proposed=proposed_roles,
            ))
        try:
            registry = namespace_contracts.namespace_registry(
                namespace.get("extensions", ())
            )
        except (TypeError, ValueError):
            registry = {}
            blockers.append(_retained_takeover_blocker(
                "RETAINED_ROOT_NAMESPACE_REGISTRY_INVALID",
                "The namespace registry cannot establish an obligation denominator.",
            ))
        candidate_roles = [candidate.get("primary_kind")]
        if type(proposed_roles) is list:
            candidate_roles.extend(proposed_roles)
        expected_obligations = sorted({
            obligation.id
            for role in candidate_roles
            if type(role) is str and role in registry
            for obligation in registry[role].obligations
        })
        current_obligations = current.get("obligations")
        current_obligation_ids = (
            sorted(current_obligations) if type(current_obligations) is dict else []
        )
        if expected_obligations != current_obligation_ids:
            blockers.append(_retained_takeover_blocker(
                "RETAINED_ROOT_OBLIGATION_SET_DIFFERS",
                "The proposed role union and retained obligation identifiers differ.",
                missing=sorted(set(expected_obligations) - set(current_obligation_ids)),
                unexpected=sorted(set(current_obligation_ids) - set(expected_obligations)),
            ))

    if audit.expected_primary == "OBJECT" and candidate.get("owned_paths"):
        blockers.append(_retained_takeover_blocker(
            "GENERIC_OBJECT_FALLBACK_ONLY",
            "Generic OBJECT ownership cannot establish a source-specific semantic takeover.",
            object_id=root_id,
            status="UNKNOWN",
        ))

    if type(proposed_operands) is dict:
        row_ids = {
            row.get("object_id")
            for row in rows
            if type(row) is dict and type(row.get("object_id")) is str
        }
        missing_targets = sorted({
            target
            for targets in proposed_operands.values()
            if type(targets) is list
            for target in targets
            if type(target) is str and target not in row_ids
        })
        if missing_targets:
            blockers.append(_retained_takeover_blocker(
                "RETAINED_ROOT_OPERAND_TARGET_MISSING",
                "A proposed operand target is not a current graph member.",
                targets=missing_targets,
            ))
        cycle = _retained_takeover_cycle(rows, root_id, proposed_operands)
        if cycle:
            blockers.append(_retained_takeover_blocker(
                "RETAINED_ROOT_OPERAND_CYCLE",
                "The proposed same-ID takeover would make the operand graph cyclic.",
                cycle=cycle,
            ))
    else:
        blockers.append(_retained_takeover_blocker(
            "RETAINED_ROOT_OPERANDS_MALFORMED",
            "The proposed operand map must be a dictionary of target lists.",
        ))

    return tuple(sorted(blockers, key=canonical_bytes))


def preview_retained_root_takeovers(
    root: Path,
    document: dict,
    *,
    semantic_specs: object | None = None,
) -> dict:
    """Plan, but never apply, the five retained-root ownership transitions."""
    rows = []
    for root_id in _RETAINED_ROOT_TAKEOVER_IDS:
        candidate = _retained_takeover_candidate(document, root_id, semantic_specs)
        blockers = retained_root_takeover_blockers(
            root, document, candidate, semantic_specs=semantic_specs
        )
        status = (
            "READY" if not blockers
            else "UNKNOWN" if any(
                blocker.get("status") == "UNKNOWN" for blocker in blockers
            )
            else "BLOCKED"
        )
        rows.append({
            "object_id": root_id,
            "status": status,
            "proposed": candidate,
            "blockers": [deepcopy(blocker) for blocker in blockers],
        })
    body = {
        "schema_version": _RETAINED_ROOT_TAKEOVER_SCHEMA,
        "status": "READY" if all(row["status"] == "READY" for row in rows) else "BLOCKED",
        "claim_boundary": (
            "Preview-only same-ID retained-root ownership planning. READY would establish "
            "only that the exact source-bound transition is structurally eligible; this "
            "function never mutates the manifest, proves mechanism truth, or executes a takeover."
        ),
        "candidates": rows,
    }
    return {**body, "digest": value_digest(body)}


def migrate(
    root: Path,
    document: dict,
    *,
    refresh_unresolved: bool = False,
    refresh_reviewed: bool = False,
    select_manifest_publication: bool = False,
    select_worker_protocol: bool = False,
    select_provenance_policy: bool = False,
    select_resource_measurement: bool = False,
    select_token_asset: bool = False,
    select_emulator_control: bool = False,
    select_harness_financial_classification: bool = False,
    select_harness_launch_profile: bool = False,
    advance_harness_launch_profile: bool = False,
    select_source_refresh_binding: bool = False,
    select_source_semantic_profile: bool = False,
    select_package_namespace_review: bool = False,
    select_compiled_consequence_graph: bool = False,
    record_review_gaps: bool = False,
    review_gaps: list[dict[str, Any]] | None = None,
    reopen_source_deltas: list[dict[str, Any]] | None = None,
    install_semantic_ownership: bool = False,
    replace_structural_instance_checks: bool = False,
    retire_package_graph_instance_check: bool = False,
) -> dict:
    """Preserve the original contract, extend ownership, never manufacture PASS.

    ``record_review_gaps`` keeps regeneration running when the reviewed catalogs trail
    the source: an unsupported primary label stays UNRESOLVED, files added after an
    audit join their object as unreviewed (a refutation over the old set reopens),
    and a refutation that cited applicability contradicts is superseded with its
    reason kept.  Each is recorded, so the verdict stays UNKNOWN; the default refuses.
    A specialization label a review no longer supports is kept with its obligations
    and appended to ``review_gaps`` when the caller passes a list.
    ``reopen_source_deltas`` names reviewed answers whose cited source changed
    meaning; after every review has been applied they are reopened rather than
    inherited, and the source profile is built over the answers that remain.
    """
    document = expand_compact_document(document)
    document = _upgrade_current_or_pre_verifier_core_harness_binding(document)
    retained = deepcopy(package_manifest.retained_contract(document))
    retained["obligation_reason_provider"] = {
        "selection_status": "SELECTED",
        "path": "reasons.vstd",
        "sha256": bytes_digest((root / "reasons.vstd").read_bytes()),
    }
    current_representations = (
        document.get("schema_version") in package_manifest.REPRESENTATION_SCHEMAS
    )
    if current_representations:
        _validate_current_or_pre_applicability_bridge(
            root,
            document,
            refresh_reviewed=refresh_reviewed,
            select_package_namespace_review=select_package_namespace_review,
            install_semantic_ownership=install_semantic_ownership,
        )
    if (
        document.get("namespace", {}).get("objects")
        and select_source_semantic_profile
        and not (refresh_reviewed and select_package_namespace_review)
    ):
        _validate_source_semantic_refresh(root, document)
    if document.get("namespace", {}).get("extensions"):
        raise ValueError("PACKAGE_MIGRATION_CUSTOM_EXTENSIONS_REQUIRE_EXPLICIT_MERGE")
    coordinate = retained["repository"]
    retained = _validate_current_or_pre_applicability_profile(
        retained,
        expected_repository=coordinate["remote"],
        expected_revision=coordinate["revision"],
    )
    # Rebinding an explicitly selected local interpreter is not changing the
    # obligation denominator. The old bytes remain in the required backup.
    for field in ("node_reconciler",):
        selected = retained[field]
        if selected["selection_status"] == "SELECTED":
            selected["sha256"] = bytes_digest((root / selected["path"]).read_bytes())
    registry = namespace_contracts.namespace_registry()
    observed = namespace_discovery.discover(root)
    observed_paths = {row["path"] for row in observed["census"]["files"]}
    _validate_core_ownership_denominator(observed_paths)
    _validate_harness_language_ownership_denominator(observed_paths)
    by_kind = {row["object_kind"]: row["object_id"] for row in retained["objects"]}
    prior_namespace_rows = document.get("namespace", {}).get("objects", [])
    prior_ids = {row["object_id"] for row in prior_namespace_rows}
    catalog_specs_by_id = {
        spec.object_id: spec
        for spec in package_semantic_ownership.SEMANTIC_OWNERSHIP_SPECS
    }
    catalog_ids = set(catalog_specs_by_id)
    named_ids = {selection[0] for selection in _NAMED.values()}
    # A legacy named row can now share an ID with its semantic successor.  The
    # ID alone therefore no longer proves that the catalog row is installed.
    # Recognize the successor by its catalog-owned rationale and accumulated
    # roles; otherwise keep treating the row as the legacy fallback.
    selected_catalog_ids = _installed_semantic_catalog_ids(
        prior_namespace_rows,
        catalog_specs_by_id,
        permit_stale_reason=refresh_reviewed,
    )
    if (
        selected_catalog_ids
        and selected_catalog_ids != catalog_ids
        and not install_semantic_ownership
    ):
        raise ValueError("PACKAGE_MIGRATION_SEMANTIC_OWNERSHIP_PARTIAL")
    semantic_active = install_semantic_ownership or bool(selected_catalog_ids)
    semantic_specs = (
        package_semantic_ownership.validate_catalog(root) if semantic_active else ()
    )
    semantic_spec_ids = [spec.object_id for spec in semantic_specs]
    if len(semantic_spec_ids) != len(set(semantic_spec_ids)):
        raise ValueError("PACKAGE_MIGRATION_SEMANTIC_OWNERSHIP_ID_DUPLICATED")
    if semantic_active and {spec.object_id for spec in semantic_specs} != catalog_ids:
        raise ValueError("PACKAGE_MIGRATION_SEMANTIC_OWNERSHIP_CATALOG_DIFFERS")
    semantic_owners = _semantic_owner_index(semantic_specs)
    semantic_specs_by_id = {spec.object_id: spec for spec in semantic_specs}
    strictly_reserved_paths = set(_HARNESS_PATHS) | set(
        _DOMAIN_IMPLEMENTATION_KINDS
    )
    if strictly_reserved_paths.intersection(semantic_owners):
        raise ValueError("PACKAGE_MIGRATION_SEMANTIC_OWNERSHIP_RESERVED_PATH")
    for path in set(_NAMED).intersection(semantic_owners):
        if semantic_owners[path] != _NAMED[path][0]:
            raise ValueError("PACKAGE_MIGRATION_SEMANTIC_OWNERSHIP_RESERVED_PATH")
    for spec in semantic_specs:
        if spec.object_id not in named_ids:
            continue
        legacy_paths = {
            path
            for path, selection in _NAMED.items()
            if selection[0] == spec.object_id
        }
        if not legacy_paths <= set(spec.owned_paths):
            raise ValueError(
                "PACKAGE_MIGRATION_SEMANTIC_OWNERSHIP_NAMED_PARTIAL"
            )
    rows = {}
    for item in tier_zero_manifest._namespace_objects(retained["objects"]):
        rows[item.object_id] = {
            **item.to_dict(),
            "specializations": [],
            "surfaces": [],
            "reason": "Retained package role: "
            + item.payload["representation_role"]
            + ". Source ownership enumerates its representation; operational truth remains a higher-tier question.",
            "classification": {},
            "obligations": {},
        }
    for identifier in sorted({selection[0] for selection in _NAMED.values()}):
        paths = tuple(
            sorted(
                path for path, selection in _NAMED.items() if selection[0] == identifier
            )
        )
        selected = _NAMED[paths[0]]
        kind, specialized = selected[1], selected[2]
        rows[identifier] = {
            "object_id": identifier,
            "kind": kind,
            # Catalog lists are module-owned constants. Returning the same list
            # would let a caller's manifest edit mutate the installed catalog.
            "specializations": list(specialized),
            "payload": {
                "representation_role": "Exact source group: " + ", ".join(paths)
            },
            "operands": {},
            "surfaces": [],
            "reason": "The exact source group has an explicit " + kind + " boundary.",
            "classification": {},
            "obligations": {},
        }
    for spec in semantic_specs:
        if spec.object_id in rows and spec.object_id not in named_ids:
            raise ValueError("PACKAGE_MIGRATION_SEMANTIC_OWNERSHIP_ID_CONFLICT")
        # A same-ID catalog row replaces only the generated legacy description;
        # it does not create a second object or change retained selections.  The
        # five named invocation-ledger paths are the first such transition.
        rows[spec.object_id] = {
            "object_id": spec.object_id,
            "kind": spec.primary_kind,
            "specializations": list(spec.specializations),
            "payload": {"representation_role": spec.representation_role},
            "operands": {role: list(targets) for role, targets in spec.operands},
            "surfaces": [],
            "reason": spec.necessity_reason + " Boundary: " + spec.consequence_boundary,
            "classification": {},
            "obligations": {},
        }
    rows[by_kind["GRAPH"]]["operands"]["members"].extend(
        sorted(set(rows) - {row["object_id"] for row in retained["objects"]})
    )
    if document.get("namespace"):
        missing = set(rows) - prior_ids
        unexpected = prior_ids - set(rows)
        if unexpected or (missing and not install_semantic_ownership):
            raise ValueError(
                "PACKAGE_MIGRATION_ADDITIONAL_OBJECTS_REQUIRE_EXPLICIT_MERGE"
            )
        if missing - catalog_ids:
            raise ValueError(
                "PACKAGE_MIGRATION_ADDITIONAL_OBJECTS_REQUIRE_EXPLICIT_MERGE"
            )
    owned_paths = {identifier: set() for identifier in rows}
    for surface in observed["surfaces"]:
        path = surface["path"]
        owner = _owner_for_path(path, by_kind, semantic_owners)
        rows[owner]["surfaces"].append(surface["surface_id"])
        owned_paths[owner].add(path)
    files = {row["path"]: row["sha256"] for row in observed["census"]["files"]}
    previous = {
        row["object_id"]: row
        for row in document.get("namespace", {}).get("objects", [])
    }
    selected_named_metadata_transitions: set[str] = set()
    if current_representations:
        for object_id in _PRE_APPLICABILITY_NAMED_METADATA_TRANSITIONS:
            prior = previous.get(object_id)
            current = rows.get(object_id)
            if prior is None or current is None:
                continue
            selected = _select_named_metadata_transition(
                object_id,
                prior,
                current_payload=current["payload"],
                current_reason=current["reason"],
                refresh_reviewed=refresh_reviewed,
                select_package_namespace_review=select_package_namespace_review,
            )
            if not selected:
                continue
            exact_paths = {
                path
                for path, named in _NAMED.items()
                if named[0] == object_id
            }
            if owned_paths.get(object_id) != exact_paths:
                raise ValueError(
                    "PACKAGE_MIGRATION_PREDECESSOR_SURFACES_DIFFER:" + object_id
                )
            selected_named_metadata_transitions.add(object_id)
    package_review_refresh = (
        _package_review_refresh_catalog()
        if refresh_reviewed and select_package_namespace_review
        else {}
    )

    def refresh_references(references: list[dict[str, str]]) -> list[dict[str, str]]:
        # Refresh selected paths only. Missing paths remain stale, and an empty
        # selection stays empty. Copying the whole source census into each new
        # question both invents evidence selection and exhausts manifest bounds.
        return [
            {"path": ref["path"], "sha256": files.get(ref["path"], ref["sha256"])}
            for ref in references
        ]

    for identifier, row in rows.items():
        evidence = [
            {"path": path, "sha256": files[path]}
            for path in sorted(owned_paths[identifier])
        ]
        # Admission reviews every installed semantic kind except deliberately
        # generic OBJECT.  Seed the complete question denominator here; a
        # missing original-kind question must not disappear merely because
        # early migrations focused on the additive consequence kinds.
        for kind in registry:
            if kind == "OBJECT":
                continue
            row["classification"][kind] = {
                "status": "UNRESOLVED",
                "reason": "Migration retains this applicability question. Static ownership alone cannot refute a "
                + kind
                + " role.",
                "evidence": [],
            }
        spec = semantic_specs_by_id.get(identifier)
        # Every original non-OBJECT primary is an explicit row declaration,
        # including the 25 retained Tier-0 objects as well as source-owned
        # semantic objects.  Added extension kinds remain owned by their
        # dedicated review catalogs, so a primary label cannot bypass their
        # independent applicability and declaration checks.
        if _is_original_primary_kind(registry, row["kind"]):
            row["classification"][row["kind"]] = {
                "status": "APPLIES",
                "reason": _primary_original_kind_reason(
                    row["kind"], row["reason"]
                ),
                "evidence": deepcopy(evidence),
            }
        if spec is not None:
            for decision in spec.root_role_decisions:
                row["classification"][decision.kind] = {
                    "status": decision.status,
                    "reason": decision.reason,
                    "evidence": deepcopy(evidence),
                }
        candidates = {
            hint
            for surface in observed["surfaces"]
            if surface["path"] in owned_paths[identifier]
            for hint in surface["hints"]
        } | {row["kind"], *row["specializations"]}
        for obligation in namespace_contracts.requirements_for(registry, candidates):
            row["obligations"][obligation["id"]] = {
                "reason": "",
                "evidence": [],
                "declaration": {
                    field: "" for field in obligation["declaration_fields"]
                },
            }
        reviewed = reviewed_declarations(identifier)
        if reviewed:
            # These declarations bind only the obligations they literally
            # name.  Classification is owned by the explicit review catalogs;
            # deriving LEDGER refutation from the absence of a LEDGER
            # declaration would manufacture a set-complement decision.
            row["obligations"].update(
                {
                    name: {
                        "reason": "The owned implementation requires this explicit boundary; the declaration does not claim execution correctness.",
                        "evidence": evidence,
                        "declaration": answers,
                    }
                    for name, answers in reviewed.items()
                }
            )
        if identifier in previous:
            semantic_named_takeover = (
                identifier in semantic_specs_by_id and identifier in named_ids
            )
            named_metadata_transition = (
                identifier in selected_named_metadata_transitions
            )
            # Reviewed classifications and obligation evidence are retained
            # below, but the catalog-owned object rationale is generated source.
            # An explicit reviewed refresh must carry a changed necessity or
            # consequence boundary into objects.vstd; otherwise automatic
            # remigration can claim CURRENT while preserving stale semantics.
            if (
                not semantic_named_takeover
                and not named_metadata_transition
                and not (
                refresh_reviewed and identifier in semantic_specs_by_id
                )
            ):
                row["reason"] = deepcopy(previous[identifier]["reason"])
            if (
                refresh_reviewed
                and spec is not None
            ):
                # The exact current catalog owns the baseline. Keep an older
                # extra role only when its prior row carries an evidenced APPLIES
                # decision and the complete obligation-key denominator.
                row["specializations"] = _reviewed_semantic_specializations(
                    row, previous[identifier], registry
                )
            elif semantic_named_takeover:
                # This is the same object, not a new row. Accumulate the exact
                # catalog roles while retaining any separately reviewed role
                # already attached to the stable ID.
                row["specializations"] = sorted(
                    set(row["specializations"])
                    | set(previous[identifier]["specializations"])
                )
            else:
                row["specializations"] = deepcopy(
                    previous[identifier]["specializations"]
                )
            if refresh_reviewed:
                # A primary kind is already necessary by declaration; retaining
                # it again as a specialization creates a false self-refinement.
                # Explicit review refresh may retire only that redundant label,
                # while preserving every genuinely additional accumulated role.
                row["specializations"] = [
                    kind for kind in row["specializations"] if kind != row["kind"]
                ]
            if (
                current_representations
                and not semantic_named_takeover
                and not named_metadata_transition
            ):
                # Current payloads are selected evidence, not regenerable role
                # templates. A coverage refresh must not silently roll them back.
                row["payload"] = deepcopy(previous[identifier]["payload"])
            # Keep every old decision and binding byte-for-byte while adding
            # unanswered questions from the expanded registry. Replacing these
            # maps would silently omit the newly necessary applicability review.
            refreshed = dict(package_review_refresh.get(identifier, {}))
            if refresh_reviewed and reviewed:
                refreshed["classification"] = frozenset(
                    set(refreshed.get("classification", ()))
                    | {"LEDGER", "TRANSACTION"}
                )
                refreshed["obligations"] = frozenset(
                    set(refreshed.get("obligations", ())) | set(reviewed)
                )
            _merge_previous_binding_maps(
                row, previous[identifier], refreshed
            )
            if refresh_unresolved:
                # Refresh only unanswered questions, never APPLIES/refutation
                # evidence or a nonempty declaration. These remain review gates.
                for decision in row["classification"].values():
                    if decision["status"] == "UNRESOLVED":
                        decision["evidence"] = refresh_references(decision["evidence"])
                for obligation in row["obligations"].values():
                    if not obligation["reason"] and not any(
                        obligation["declaration"].values()
                    ):
                        obligation["evidence"] = refresh_references(
                            obligation["evidence"]
                        )
    _prepare_local_reviews_without_compiled_consequences(rows, previous)
    if select_source_refresh_binding:
        source_coordinate, _ = source_refresh_coordinate(root)
        rows[by_kind["GRAPH"]]["payload"]["source_refresh_coordinate"] = (
            source_coordinate
        )
    _rehome_unresolved_candidate_evidence(
        rows,
        previous,
        observed,
        {path: _owner_for_path(path, by_kind, semantic_owners) for path in files},
    )
    if select_package_namespace_review:
        # Apply every source-partitioned original-kind review, not only the
        # retained rows.  Each catalog remains fail-closed for undecided cells;
        # this step can migrate established decisions but cannot turn an
        # unresolved classification into an exemption.
        # The strict policy calls each review exactly as it always has; only the
        # recording policy passes the extra keyword.
        recording = {"record_gaps": True} if record_review_gaps else {}
        original_kind_recording = (
            {
                "record_gaps": True,
                "documented_retention_keys": _documented_applies_keys(root),
            }
            if record_review_gaps
            else {}
        )
        rows = package_original_kind_catalog.apply_partial_profiles(
            root, rows, files, **original_kind_recording
        )
        rows = package_namespace_review.apply_package_namespace_review(
            root, rows, files, **recording
        )
        rows = _review_stage(
            "records",
            package_semantic_review_records.apply_package_semantic_review_records,
            root,
            rows,
            files,
            record_review_gaps,
            review_gaps,
        )
        rows = _review_stage(
            "operations",
            package_semantic_review_operations.apply_package_semantic_review_operations,
            root,
            rows,
            files,
            record_review_gaps,
            review_gaps,
        )
        rows = _review_stage(
            "subjects",
            package_semantic_review_subjects.apply_package_semantic_review_subjects,
            root,
            rows,
            files,
            record_review_gaps,
            review_gaps,
        )
        rows = _review_stage(
            "verifier",
            package_semantic_review_verifier.apply_package_semantic_review_verifier,
            root,
            rows,
            files,
            record_review_gaps,
            review_gaps,
        )
        rows = _review_stage(
            "scripts",
            package_semantic_review_scripts.apply_package_semantic_review_scripts,
            root,
            rows,
            files,
            record_review_gaps,
            review_gaps,
        )
        rows = _review_stage(
            "admission",
            package_semantic_review_admission.apply_package_semantic_review_admission,
            root,
            rows,
            files,
            record_review_gaps,
            review_gaps,
        )
        rows = _review_stage(
            "commands",
            package_semantic_review_commands.apply_package_semantic_review_commands,
            root,
            rows,
            files,
            record_review_gaps,
            review_gaps,
        )
        rows = _review_stage(
            "hardware_cli",
            package_semantic_review_hardware_cli.apply_package_semantic_review_hardware_cli,
            root,
            rows,
            files,
            record_review_gaps,
            review_gaps,
        )
        rows = _review_stage(
            "partitions",
            package_semantic_review_partitions.apply_package_semantic_review_partitions,
            root,
            rows,
            files,
            record_review_gaps,
            review_gaps,
        )
        rows = _review_stage(
            "polish",
            package_semantic_review_polish.apply_package_semantic_review_polish,
            root,
            rows,
            files,
            record_review_gaps,
            review_gaps,
        )
        rows = _review_stage(
            "self_polish",
            package_semantic_review_self_polish.apply_package_semantic_review_self_polish,
            root,
            rows,
            files,
            record_review_gaps,
            review_gaps,
        )
        rows = _review_stage(
            "people",
            package_original_review_people.apply_package_original_review_people,
            root,
            rows,
            files,
            record_review_gaps,
            review_gaps,
        )
        rows = _review_stage(
            "systems",
            package_original_review_systems.apply_package_original_review_systems,
            root,
            rows,
            files,
            record_review_gaps,
            review_gaps,
        )
        rows = _review_stage(
            "computation",
            package_original_review_computation.apply_package_original_review_computation,
            root,
            rows,
            files,
            record_review_gaps,
            review_gaps,
            **({"record_gaps": True, "gaps": review_gaps} if record_review_gaps else {}),
        )
        def _parent_reviews() -> None:
            nonlocal rows
            for name, apply, reviewed in (
                (
                    "core",
                    package_semantic_review_core.apply_package_semantic_review_core,
                    {
                        package_semantic_review_core.CORE_OBJECT_ID: (
                            package_semantic_review_core.CORE_PATHS
                        )
                    },
                ),
                (
                    "package_object",
                    package_semantic_review_package_object.apply_package_semantic_review_package_object,
                    {
                        package_semantic_review_package_object.PACKAGE_OBJECT_ID: (
                            package_semantic_review_package_object.PACKAGE_OBJECT_PATHS
                        )
                    },
                ),
            ):
                rows = _review_stage(
                    name,
                    apply,
                    root,
                    rows,
                    files,
                    record_review_gaps,
                    review_gaps,
                    reviewed=reviewed,
                )

        if package_review_refresh:
            # The explicit refresh has already retired the old catalog-owned
            # answers. Review the two broad parents on their current, reduced
            # ownership before deciding whether any historical child transfer
            # still needs retirement. This makes the current parent reviews
            # independent instead of mistaking rehomed candidate evidence for
            # an idempotent historical transfer.
            _parent_reviews()
            _retire_transferred_reviews(rows, files, registry)
        else:
            _retire_transferred_reviews(rows, files, registry)
            _parent_reviews()
        if package_review_refresh:
            for object_id in package_review_refresh:
                prior = previous.get(object_id)
                if prior is None:
                    continue
                _require_reviewed_answers_survive(
                    object_id,
                    prior,
                    rows[object_id],
                    record=record_review_gaps,
                    gaps=review_gaps,
                )
    if select_harness_financial_classification:
        _select_harness_financial_classification(
            root,
            rows[by_kind["HARNESS"]],
            files,
            refresh_reviewed=refresh_reviewed,
        )
    _refresh_harness_launch_denominator(
        root,
        rows[by_kind["HARNESS"]],
        previous.get(by_kind["HARNESS"]),
        select_profile=select_harness_launch_profile,
        refresh_reviewed=refresh_reviewed,
        advance_reviewed=advance_harness_launch_profile,
    )
    if reopen_source_deltas:
        reopened_gaps = _reopen_rows(rows, reopen_source_deltas, previous)
        if review_gaps is not None:
            review_gaps.extend(reopened_gaps)
    # Membership is final here, so ordinary refresh keeps the root's derived commitments
    # consistent with it.  An explicit retirement instead validates the commitments the
    # maintainer enriched and refuses a wrong one; it never repairs them.
    if not retire_package_graph_instance_check:
        _refresh_package_graph_dependency_commitments(
            rows, registry, by_kind["GRAPH"]
        )
    if select_source_semantic_profile:
        rows[by_kind["GRAPH"]]["payload"]["source_semantic_profile"] = (
            source_semantic_profile(root, rows)
        )
    namespace = {
        "schema_version": namespace_manifest.SCHEMA,
        "extensions": [],
        "registry_digest": namespace_contracts.registry_document(registry)["digest"],
        "objects": list(rows.values()),
    }
    if "consequence_graph" in document.get("namespace", {}):
        # Migration does not rediscover effects or authorize replacing selected
        # evidence. Even stale bindings must survive for an explicit review.
        namespace["consequence_graph"] = deepcopy(
            document["namespace"]["consequence_graph"]
        )
    if "instance_checks" in document.get("namespace", {}):
        namespace["instance_checks"] = deepcopy(
            document["namespace"]["instance_checks"]
        )
        if replace_structural_instance_checks:
            if document.get("schema_version") not in package_manifest.SCHEMAS:
                raise ValueError(
                    "PACKAGE_MIGRATION_STRUCTURAL_REPLACEMENT_REQUIRES_ADDITIVE_PACKAGE"
                )
            _replace_structural_instance_checks(namespace, registry)
    if "execution_checks" in document.get("namespace", {}):
        namespace["execution_checks"] = deepcopy(
            document["namespace"]["execution_checks"]
        )
        if semantic_active:
            _rehome_execution_checks(namespace, rows, semantic_owners)
    if select_manifest_publication:
        from verifier.runtime import manifest_write_execution

        path = manifest_write_execution.IMPLEMENTATION
        installed = Path(manifest_write_execution.__file__).with_name(
            "namespace_cli.py"
        )
        if files.get(path) != bytes_digest(installed.read_bytes()):
            raise ValueError("PACKAGE_MIGRATION_PUBLICATION_IMPLEMENTATION_DIFFERS")
        selection = {
            "object_id": "vstd-manifest-write",
            "mechanism": manifest_write_execution.ADAPTER,
            "reason": "This object owns the installed manifest template and formatter handlers. Fresh private-file executions test their preconditions, publication failures and retry boundaries without touching operator manifests.",
            "evidence": [{"path": path, "sha256": files[path]}],
        }
        checks = namespace.setdefault("execution_checks", [])
        _upsert_execution_check(
            checks, selection, refresh_reviewed=refresh_reviewed
        )
    if select_worker_protocol:
        from verifier.runtime import worker_protocol_execution

        _select_worker_protocol(
            root,
            namespace,
            _execution_owner_row(
                rows,
                semantic_owners,
                semantic_active=semantic_active,
                mechanism=worker_protocol_execution.ADAPTER,
                fallback_owner=by_kind["VERIFIER"],
            ),
            files,
            refresh_reviewed=refresh_reviewed,
        )
    if select_provenance_policy:
        from verifier.runtime import provenance_policy_execution

        _select_provenance_policy(
            root,
            namespace,
            _execution_owner_row(
                rows,
                semantic_owners,
                semantic_active=semantic_active,
                mechanism=provenance_policy_execution.ADAPTER,
                fallback_owner=by_kind["OBJECT"],
            ),
            files,
            refresh_reviewed=refresh_reviewed,
        )
    if select_resource_measurement:
        _select_resource_measurement(
            root,
            namespace,
            rows[by_kind["SIM"]],
            files,
            refresh_reviewed=refresh_reviewed,
        )
    if select_token_asset:
        from verifier.runtime import token_asset_execution

        _select_token_asset(
            root,
            namespace,
            _execution_owner_row(
                rows,
                semantic_owners,
                semantic_active=semantic_active,
                mechanism=token_asset_execution.ADAPTER,
                fallback_owner=next(
                    identifier for identifier, row in rows.items()
                    if row.get("object_id") == "vstd-token"
                ),
            ),
            files,
            refresh_reviewed=refresh_reviewed,
        )
    if select_emulator_control:
        from verifier.runtime import emulator_control_execution

        _select_emulator_control(
            root,
            namespace,
            _execution_owner_row(
                rows,
                semantic_owners,
                semantic_active=semantic_active,
                mechanism=emulator_control_execution.ADAPTER,
                fallback_owner=next(
                    identifier for identifier, row in rows.items()
                    if row.get("object_id")
                    == "vstd-firmware-emulator-accounting"
                ),
            ),
            files,
            refresh_reviewed=refresh_reviewed,
        )
    if select_compiled_consequence_graph:
        if not refresh_reviewed:
            raise ValueError(
                "PACKAGE_MIGRATION_CONSEQUENCE_GRAPH_REQUIRES_REVIEW_REFRESH"
            )
        prior_graph = document.get("namespace", {}).get("consequence_graph")
        if prior_graph is not None and not (
            namespace_consequences.is_compiled_effect_graph(
                prior_graph, document["namespace"]["objects"]
            )
            or namespace_consequences.is_pre_reviewed_control_compiled_effect_graph(
                prior_graph, document["namespace"]["objects"]
            )
            or namespace_consequences.is_legacy_compiled_effect_graph(
                prior_graph, document["namespace"]["objects"]
            )
        ):
            raise ValueError(
                "PACKAGE_MIGRATION_CONSEQUENCE_GRAPH_SELECTION_CONFLICT"
            )
        namespace["consequence_graph"] = (
            namespace_consequences.compile_reviewed_effect_graph(
                list(rows.values()), registry, observed
            )
        )
    # Consequence retention is a compiler invariant of the fully selected
    # graph, not an opt-in local source-review family.  Run it only after
    # selected execution adapters have installed their final roles and checks;
    # deriving earlier can miss consequences those selections add.  Admission
    # uses EMPTY when no explicit consequence_graph is stored because typed
    # operand edges still imply roles; migration must use the same denominator.
    consequence_graph = namespace.get(
        "consequence_graph", namespace_consequences.EMPTY
    )
    derived_consequences = namespace_consequences.derive_consequences(
        list(rows.values()),
        registry,
        observed,
        consequence_graph,
    )
    _apply_required_consequence_kinds(
        rows,
        previous,
        observed,
        registry,
        derived_consequences["required_kinds"],
    )
    # Direct ``migrate`` callers may supply an in-memory predecessor without an
    # installed root file.  A documented-reason compilation is valid only when
    # the selector can bind the sole ledger to the exact co-located registry;
    # ordinary root refresh always has that file.
    if (root / "objects.vstd").is_file():
        _apply_documented_obligation_bindings(root, rows, observed, registry)
    _compact_compiled_classification_reasons(rows)
    result = {
        **retained,
        "schema_version": package_manifest.SCHEMA,
        "namespace": namespace,
    }
    if current_representations:
        result.update(
            schema_version=(
                package_manifest.PACKAGE_REPRESENTATION_SCHEMA
                if document.get("schema_version")
                == package_manifest.PACKAGE_REPRESENTATION_SCHEMA
                else package_manifest.REPRESENTATION_SCHEMA
            ),
            representation_updates=(
                _refreshed_representation_updates(
                    document,
                    retained,
                    rows,
                    registry,
                    files,
                    select_harness_launch_profile=select_harness_launch_profile,
                )
                if document.get("representation_updates")
                else []
            ),
        )
    if retire_package_graph_instance_check:
        if document.get("schema_version") not in package_manifest.SCHEMAS:
            raise ValueError(
                "PACKAGE_MIGRATION_PACKAGE_GRAPH_RETIREMENT_REQUIRES_ADDITIVE_PACKAGE"
            )
        _retire_package_graph_instance_check(
            namespace,
            registry,
            by_kind["GRAPH"],
            result.get("representation_updates", []),
            files,
        )
    encoded_size = len(canonical_bytes(result)) + 1
    try:
        structure_nodes = namespace_manifest.structure_node_count(
            result,
            limit=namespace_manifest.MAX_PACKAGE_NAMESPACE_NODES,
        )
    except ValueError as exc:
        if str(exc) == "NAMESPACE_MANIFEST_STRUCTURE_CAPACITY":
            raise ValueError(
                "PACKAGE_MIGRATION_MANIFEST_STRUCTURE_CAPACITY_EXHAUSTED"
            ) from exc
        raise
    if (
        encoded_size > tier_zero_manifest.MAX_EXTENDED_MANIFEST_BYTES
        or structure_nodes > namespace_manifest.MAX_NAMESPACE_NODES
    ):
        # Version 5 changes only the bounded transport profile.  It retains the
        # v4 representation contract and never authorizes dropping declarations
        # merely to make a complete package graph fit an older byte ceiling.
        result["schema_version"] = package_manifest.PACKAGE_REPRESENTATION_SCHEMA
        result.setdefault("representation_updates", [])
        encoded_size = len(canonical_bytes(result)) + 1
        try:
            namespace_manifest.structure_node_count(
                result,
                limit=namespace_manifest.MAX_PACKAGE_NAMESPACE_NODES,
            )
        except ValueError as exc:
            if str(exc) == "NAMESPACE_MANIFEST_STRUCTURE_CAPACITY":
                raise ValueError(
                    "PACKAGE_MIGRATION_MANIFEST_STRUCTURE_CAPACITY_EXHAUSTED"
                ) from exc
            raise
    inline_encoded_size = encoded_size
    if (
        encoded_size > tier_zero_manifest.MAX_PACKAGE_MANIFEST_BYTES
        or result["schema_version"]
        == package_manifest.PACKAGE_REPRESENTATION_SCHEMA
        and encoded_size > _COMPACT_TRANSPORT_PREFERRED_BYTES
    ):
        # Version 6 changes only how repeated evidence arrays are transported.
        # The encoder first validates the complete inline namespace and then
        # proves that normalizing its digest selectors reproduces those exact
        # semantics.  This is therefore a bounded representation change, not
        # authority to omit a decision, reason, declaration, or evidence item.
        compact_result = deepcopy(result)
        try:
            compact_result["namespace"] = namespace_manifest.compact_manifest(
                compact_result["namespace"]
            )
        except ValueError as exc:
            if str(exc) in {
                "NAMESPACE_MANIFEST_STRUCTURE_CAPACITY",
                "NAMESPACE_COMPACT_EXPANDED_STRUCTURE_CAPACITY",
            }:
                raise ValueError(
                    "PACKAGE_MIGRATION_MANIFEST_STRUCTURE_CAPACITY_EXHAUSTED"
                ) from exc
            if str(exc) == "NAMESPACE_COMPACT_EXPANDED_BYTE_CAPACITY":
                raise ValueError(
                    "PACKAGE_MIGRATION_MANIFEST_CAPACITY_EXHAUSTED"
                ) from exc
            raise
        compact_result["schema_version"] = (
            package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA
        )
        compact_result.setdefault("representation_updates", [])
        compact_encoded_size = len(canonical_bytes(compact_result)) + 1
        if (
            compact_encoded_size < inline_encoded_size
            or inline_encoded_size
            > tier_zero_manifest.MAX_PACKAGE_MANIFEST_BYTES
        ):
            result = compact_result
            encoded_size = compact_encoded_size
            try:
                namespace_manifest.structure_node_count(
                    result,
                    limit=namespace_manifest.MAX_PACKAGE_NAMESPACE_NODES,
                )
            except ValueError as exc:
                if str(exc) == "NAMESPACE_MANIFEST_STRUCTURE_CAPACITY":
                    raise ValueError(
                        "PACKAGE_MIGRATION_MANIFEST_STRUCTURE_CAPACITY_EXHAUSTED"
                    ) from exc
                raise
    if encoded_size > tier_zero_manifest.MAX_PACKAGE_MANIFEST_BYTES:
        raise ValueError("PACKAGE_MIGRATION_MANIFEST_CAPACITY_EXHAUSTED")
    package_manifest.select(
        result, repository=coordinate["remote"], revision=coordinate["revision"]
    )
    return result


def selected_refresh_options(document: dict) -> dict[str, bool]:
    """Recover only migration choices already selected by ``document``.

    Automatic refresh is deliberately narrower than the maintainer command: it
    may update current source bindings and extend an already installed review
    catalog, but it must not opt a repository into a new execution mechanism or
    semantic review policy merely because a newer Verifier knows about one.
    """

    document = expand_compact_document(document)
    namespace = document.get("namespace", {})
    rows = namespace.get("objects", [])
    mechanisms = {
        row.get("mechanism")
        for row in namespace.get("execution_checks", [])
        if type(row) is dict
    }
    semantic_specs_by_id = {
        spec.object_id: spec
        for spec in package_semantic_ownership.SEMANTIC_OWNERSHIP_SPECS
    }
    installed_semantic_ids = _installed_semantic_catalog_ids(
        rows, semantic_specs_by_id
    )
    installed_review_ids = _installed_package_review_ids(rows)
    harness = next(
        (
            row
            for row in rows
            if type(row) is dict and row.get("object_id") == "vstd-harness"
        ),
        {},
    )
    harness_classification = harness.get("classification", {})
    financial_selected = any(
        type(harness_classification.get(kind)) is dict
        and harness_classification[kind].get("status") != "UNRESOLVED"
        for kind in ("LEDGER", "TRANSACTION")
    )
    harness_payload = harness.get("payload", {})
    launch_profile_selected = (
        type(harness_payload) is dict
        and "direct_launch_denominator" in harness_payload
    )
    graph = next(
        (
            row
            for row in rows
            if type(row) is dict and row.get("object_id") == "vstd-package-graph"
        ),
        {},
    )
    source_refresh_selected = (
        type(graph.get("payload")) is dict
        and "source_refresh_coordinate" in graph["payload"]
    )
    source_semantic_profile_selected = (
        type(graph.get("payload")) is dict
        and "source_semantic_profile" in graph["payload"]
    )
    valid_source_semantic_profile = False
    if source_semantic_profile_selected:
        try:
            validated_source_semantic_profile = _validated_source_semantic_profile(
                graph["payload"]["source_semantic_profile"]
            )
        except (KeyError, TypeError, ValueError):
            pass
        else:
            valid_source_semantic_profile = _source_semantic_profile_matches_rows(
                validated_source_semantic_profile, rows
            )
    review_catalog_ids = set(_package_review_refresh_catalog())
    complete_review_lifecycle = (
        bool(review_catalog_ids)
        and installed_review_ids == review_catalog_ids
        and valid_source_semantic_profile
    )
    return {
        "select_manifest_publication": (
            "verifier-manifest-publication-1" in mechanisms
        ),
        "select_worker_protocol": "verifier-worker-protocol-1" in mechanisms,
        "select_provenance_policy": (
            "verifier-provenance-policy-1" in mechanisms
        ),
        "select_resource_measurement": (
            "verifier-resource-measurement-1" in mechanisms
        ),
        "select_token_asset": "verifier-token-asset-1" in mechanisms,
        "select_emulator_control": "verifier-emulated-control-1" in mechanisms,
        "select_harness_financial_classification": financial_selected,
        "select_harness_launch_profile": launch_profile_selected,
        "select_source_refresh_binding": source_refresh_selected,
        "select_source_semantic_profile": source_semantic_profile_selected,
        "select_package_namespace_review": complete_review_lifecycle,
        "select_compiled_consequence_graph": (
            namespace_consequences.is_compiled_effect_graph(
                namespace.get("consequence_graph"), rows
            )
            or namespace_consequences.is_pre_reviewed_control_compiled_effect_graph(
                namespace.get("consequence_graph"), rows
            )
            or namespace_consequences.is_legacy_compiled_effect_graph(
                namespace.get("consequence_graph"), rows
            )
        ),
        "install_semantic_ownership": bool(installed_semantic_ids),
        # Replacing a selected check changes evidence authority.  That remains
        # an explicit maintainer migration, never an automatic source refresh.
        "replace_structural_instance_checks": False,
        "retire_package_graph_instance_check": False,
    }


def expand_compact_document(document: dict) -> dict:
    """Return the inline version-5 form of a compact version-6 root.

    A compact namespace stores evidence-set pointers, while every reviewed-answer
    gate below reads the evidence arrays themselves. Expansion is the exact
    inverse of the compact transport (``normalize_manifest`` proves it), so the
    gates see the same semantics a version-5 root would show. Any other document
    is returned unchanged, and the stored document is never mutated.
    """

    if document.get("schema_version") != package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA:
        return document
    expanded = {key: value for key, value in document.items() if key != "namespace"}
    expanded = deepcopy(expanded)
    expanded["schema_version"] = package_manifest.PACKAGE_REPRESENTATION_SCHEMA
    expanded["namespace"] = namespace_manifest.normalize_manifest(document["namespace"])
    return expanded


def refresh_selected_manifest(
    root: Path,
    document: dict,
    *,
    record_review_gaps: bool = False,
    review_gaps: list[dict[str, Any]] | None = None,
    source_deltas: list[dict[str, Any]] | None = None,
) -> dict:
    """Regenerate current bindings without inventing new selected policies.

    With ``record_review_gaps`` every review stage records, rather than refuses, the
    gaps it meets and appends them to ``review_gaps``; unanswered questions stay
    unanswered.  ``source_deltas`` then names the reviewed answers whose source
    changed meaning, which are reopened instead of refusing the whole refresh.  The
    default is the maintainer's refusing policy.
    """

    document = expand_compact_document(document)
    options: dict[str, Any] = dict(selected_refresh_options(document))
    if options["select_source_semantic_profile"] and not (
        record_review_gaps and source_deltas is not None
    ):
        _validate_source_semantic_refresh(root, document)
    if record_review_gaps:
        options["record_review_gaps"] = True
        options["review_gaps"] = review_gaps
        options["reopen_source_deltas"] = source_deltas
        # A manifest that already carries reviewed package answers has opted into
        # the review lifecycle.  Recording gaps lets the catalogs extend it to
        # objects and kinds added since, instead of freezing it at the old shape.
        if _installed_package_review_ids(document["namespace"]["objects"]):
            options["select_package_namespace_review"] = True
    return migrate(
        root,
        document,
        refresh_unresolved=True,
        refresh_reviewed=True,
        **options,
    )


def _select_worker_protocol(
    root: Path,
    namespace: dict,
    row: dict,
    files: dict[str, str],
    *,
    refresh_reviewed: bool = False,
) -> None:
    """Opt into one reviewed role; never replace a prior decision or selection."""
    from verifier.runtime import worker_protocol_execution as execution

    path = execution.IMPLEMENTATION
    installed = Path(execution.__file__).with_name("package_execution.py")
    if (
        files.get(path) != bytes_digest(installed.read_bytes())
        or "file:" + path not in row["surfaces"]
    ):
        raise ValueError("PACKAGE_MIGRATION_PROTOCOL_IMPLEMENTATION_DIFFERS")
    evidence = [{"path": path, "sha256": files[path]}]
    reason = "The owned installed dispatcher implements a fixed local request/reply protocol; this does not authenticate the host or establish confinement."
    if row.get("object_id") == "vstd-package-worker-exchange":
        reviewed = _canonical_review_selection(
            root,
            row,
            files,
            package_semantic_review_operations,
            "PROTOCOL",
            "PACKAGE_MIGRATION_PROTOCOL",
            refresh_reviewed=refresh_reviewed,
        )
        selected = {
            "object_id": row["object_id"],
            "mechanism": execution.ADAPTER,
            "reason": reason,
            "evidence": evidence,
        }
        checks = namespace.setdefault("execution_checks", [])
        staged_checks = deepcopy(checks)
        _upsert_execution_check(
            staged_checks, selected, refresh_reviewed=refresh_reviewed
        )
        row["classification"]["PROTOCOL"] = reviewed["decision"]
        row["obligations"].update(reviewed["bindings"])
        checks[:] = staged_checks
        return
    decision = {"status": "APPLIES", "reason": reason, "evidence": evidence}
    previous = row["classification"]["PROTOCOL"]
    if _review_decision_conflicts(
        previous, decision, refresh_reviewed=refresh_reviewed
    ):
        raise ValueError("PACKAGE_MIGRATION_PROTOCOL_DECISION_CONFLICT")
    declarations = {
        "PROTOCOL-0.1-participants-and-states": {
            "participants": "Installed dispatcher and one selected fixed local worker process.",
            "roles": "Dispatcher captures source and request; worker returns observations; parent checks correspondence before route predicates.",
            "states": "Source capture, launch, reply parsing, request/source validation, return or refusal.",
            "transitions": "Only zero exit, bounded strict output, exact request and recaptured source pins permit return.",
        },
        "PROTOCOL-0.2-ordering-and-replay": {
            "message_authority": "Closed installed worker selection and host interpreter are trust assumptions; no external authentication claim.",
            "ordering": "One request and one captured terminal response per invocation; no multiplexed or distributed ordering claim.",
            "replay": "Fresh nonce plus exact object and collection commitments; failed launches do not automatically retry.",
            "compatibility": "Exact registered request and response versions; no implicit version negotiation.",
        },
        "PROTOCOL-0.3-failures-and-progress": {
            "failure_assumptions": "Trusted host interpreter, filesystem and subprocess transport; injected faults are finite controls, not arbitrary-host safety.",
            "safety": "Malformed, substituted, stale or oversized replies cannot supply a validated exchange.",
            "liveness": "A 30-second subprocess timeout bounds waiting under the host contract; output is bounded after capture, not streaming memory.",
            "recovery": "Unavailable execution remains UNKNOWN; invalid response remains FAIL at evaluation; neither authorizes automatic retry.",
        },
    }
    selected = {
        "object_id": row["object_id"],
        "mechanism": execution.ADAPTER,
        "reason": reason,
        "evidence": evidence,
    }
    checks = namespace.setdefault("execution_checks", [])
    # The execution selection is part of the same reviewed transaction as the
    # role and declaration bindings.  Validate it before mutating the owner so
    # a conflicting prior selection cannot leave a half-selected PROTOCOL.
    staged_checks = deepcopy(checks)
    _upsert_execution_check(
        staged_checks, selected, refresh_reviewed=refresh_reviewed
    )
    for name, answers in declarations.items():
        binding = {"reason": reason, "evidence": evidence, "declaration": answers}
        previous = row["obligations"].get(name)
        if _review_binding_conflicts(
            previous, binding, refresh_reviewed=refresh_reviewed
        ):
            raise ValueError("PACKAGE_MIGRATION_PROTOCOL_DECLARATION_CONFLICT")
        row["obligations"][name] = binding
    row["classification"]["PROTOCOL"] = decision
    if row.get("kind") != "PROTOCOL" and "PROTOCOL" not in row["specializations"]:
        row["specializations"].append("PROTOCOL")
    checks[:] = staged_checks


def _select_provenance_policy(
    root: Path,
    namespace: dict,
    row: dict,
    files: dict[str, str],
    *,
    refresh_reviewed: bool = False,
) -> None:
    """Add a reviewed executable POLICY role, never an assumed authority grant."""
    from verifier.runtime import provenance_policy_execution as execution

    path = execution.IMPLEMENTATION
    installed = Path(execution.__file__).parents[1] / "data/policy.py"
    if (
        files.get(path) != bytes_digest(installed.read_bytes())
        or "file:" + path not in row["surfaces"]
    ):
        raise ValueError("PACKAGE_MIGRATION_POLICY_IMPLEMENTATION_DIFFERS")
    evidence = [{"path": path, "sha256": files[path]}]
    reason = "The owned installed provenance-policy engine decides recorded-lineage predicates; this is neither provenance truth nor license authority or downstream enforcement."
    if row.get("object_id") == "vstd-dataset-provenance-policy":
        reviewed = _canonical_review_selection(
            root,
            row,
            files,
            package_semantic_review_records,
            "POLICY",
            "PACKAGE_MIGRATION_POLICY",
            refresh_reviewed=refresh_reviewed,
        )
        selected = {
            "object_id": row["object_id"],
            "mechanism": execution.ADAPTER,
            "reason": reason,
            "evidence": evidence,
        }
        checks = namespace.setdefault("execution_checks", [])
        staged_checks = deepcopy(checks)
        _upsert_execution_check(
            staged_checks, selected, refresh_reviewed=refresh_reviewed
        )
        row["classification"]["POLICY"] = reviewed["decision"]
        row["obligations"].update(reviewed["bindings"])
        checks[:] = staged_checks
        return
    decision = {"status": "APPLIES", "reason": reason, "evidence": evidence}
    previous = row["classification"]["POLICY"]
    if _review_decision_conflicts(
        previous, decision, refresh_reviewed=refresh_reviewed
    ):
        raise ValueError("PACKAGE_MIGRATION_POLICY_DECISION_CONFLICT")
    declarations = {
        "POLICY-0.1-rules-and-precedence": {
            "scope": "Three distinct predicates over the selected target's recorded ancestor closure, including the target itself.",
            "decision_inputs": "ProvenanceHypergraph, target identifier, recorded statuses/rights and optional approved license identifiers.",
            "precedence": "Structural validity precedes decision. Grounded encoding is authoritative; solver/direct disagreements raise rather than choosing a preferred answer.",
            "defaults": "No-revoked differs from all-valid; missing target and rootless license evidence are indeterminate. Missing rights do not satisfy approval; explicit empty license selection stays empty.",
        },
        "POLICY-0.2-authority-and-exceptions": {
            "authority": "The caller selects the graph, predicate and license list; authenticity of metadata and legal authority are outside this implementation.",
            "exceptions": "No override argument bypasses structural or encoding checks; selecting a different predicate is a different named claim.",
            "revisions": "Installed source defines each rule. Explicit per-call license selections replace that call's default list; there is no persistent revision service.",
            "activation": "Each invocation reads its supplied graph and configuration; no cached approval or external enforcement activation is promised.",
        },
        "POLICY-0.3-enforcement-and-decisions": {
            "enforcement_points": "All three public verification methods validate structure and certify their emitted encoding before a determined result.",
            "decision_evidence": "Results carry policy/target identifiers, verdict, clauses and variable map. Encoding errors may retain a kernel-checkable certificate; normal result records do not export it.",
            "bypass_handling": "Malformed lineage and contradictory or incomplete encodings refuse; downstream callers remain responsible for enforcing these decisions.",
            "unavailable_behavior": "An absent target or rootless source-license question is INDETERMINATE, not successful compliance. Unsupported external truth is not inferred.",
        },
    }
    bindings = {
        name: {"reason": reason, "evidence": evidence, "declaration": answers}
        for name, answers in declarations.items()
    }
    for name, binding in bindings.items():
        previous = row["obligations"].get(name)
        if _review_binding_conflicts(
            previous, binding, refresh_reviewed=refresh_reviewed
        ):
            raise ValueError("PACKAGE_MIGRATION_POLICY_DECLARATION_CONFLICT")
    selected = {
        "object_id": row["object_id"],
        "mechanism": execution.ADAPTER,
        "reason": reason,
        "evidence": evidence,
    }
    checks = namespace.get("execution_checks", [])
    staged_checks = deepcopy(checks)
    _upsert_execution_check(
        staged_checks, selected, refresh_reviewed=refresh_reviewed
    )
    # Do not partially update the draft if any reviewed answer conflicts.
    row["classification"]["POLICY"] = decision
    row["obligations"].update(bindings)
    if row.get("kind") != "POLICY" and "POLICY" not in row["specializations"]:
        row["specializations"].append("POLICY")
    namespace.setdefault("execution_checks", [])[:] = staged_checks


def _select_resource_measurement(
    root: Path,
    namespace: dict,
    row: dict,
    files: dict[str, str],
    *,
    refresh_reviewed: bool = False,
) -> None:
    """Bind both actual meter roles, without assuming physical sensor accuracy."""
    from verifier.runtime import resource_measurement_execution as execution

    paths = [
        execution.IMPLEMENTATION,
        "src/verifier/domains/contracts/sim_fresh_worker.py",
        "src/verifier/domains/contracts/sim_fresh_bootstrap.py",
    ]
    installed = Path(execution.__file__).parents[1]
    for path in paths:
        if (
            files.get(path)
            != bytes_digest(
                (installed / path.removeprefix("src/verifier/")).read_bytes()
            )
            or "file:" + path not in row["surfaces"]
        ):
            raise ValueError("PACKAGE_MIGRATION_MEASUREMENT_IMPLEMENTATION_DIFFERS")
    evidence = [{"path": path, "sha256": files[path]} for path in paths]
    reason = "The owned fresh transition meter acquires and validates thread CPU nanoseconds and peak traced Python allocation bytes; software resource observations require both MEASUREMENT and SENSOR roles, not physical calibration claims."
    if row.get("object_id") == "vstd-simulation":
        reviewed = {
            kind: _canonical_review_selection(
                root,
                row,
                files,
                package_namespace_review,
                kind,
                "PACKAGE_MIGRATION_MEASUREMENT",
                refresh_reviewed=refresh_reviewed,
            )
            for kind in ("MEASUREMENT", "SENSOR")
        }
        selected = {
            "object_id": row["object_id"],
            "mechanism": execution.ADAPTER,
            "reason": reason,
            "evidence": evidence,
        }
        checks = namespace.setdefault("execution_checks", [])
        staged_checks = deepcopy(checks)
        _upsert_execution_check(
            staged_checks, selected, refresh_reviewed=refresh_reviewed
        )
        for kind, selection in reviewed.items():
            row["classification"][kind] = selection["decision"]
            row["obligations"].update(selection["bindings"])
            if row.get("kind") != kind and kind not in row["specializations"]:
                row["specializations"].append(kind)
        checks[:] = staged_checks
        return
    decision = {"status": "APPLIES", "reason": reason, "evidence": evidence}
    for kind in ("MEASUREMENT", "SENSOR"):
        previous = row["classification"][kind]
        if _review_decision_conflicts(
            previous, decision, refresh_reviewed=refresh_reviewed
        ):
            raise ValueError("PACKAGE_MIGRATION_MEASUREMENT_DECISION_CONFLICT")
    declarations = {
        "MEASUREMENT-0.1-phenomenon-and-method": {
            "phenomenon": "Resource use within each selected finite interpreter transition, not validation or process startup.",
            "method": "CPython thread_time_ns differences and per-transition tracemalloc peak readings.",
            "source": "Fresh source-loaded sim_fresh_worker validated by sim_resource_fresh and its closed bootstrap.",
            "observation_vs_estimate": "Direct local instrument readings, not budget counters or extrapolated physical-device usage.",
        },
        "MEASUREMENT-0.2-units-time-and-uncertainty": {
            "units": "Thread CPU nanoseconds and peak traced Python allocation bytes; no total resident memory or whole-device claim.",
            "reference_frame": "The isolated worker's executing thread and Python allocation tracer, indexed by trajectory step.",
            "observation_time": "Each transition interval; elapsed thread time is not a wall-clock timestamp.",
            "arrival_time": "Parent receives the bounded completed process response; no absolute arrival timestamp or latency guarantee is exported.",
            "uncertainty": "Instrument resolution, tracer overhead, host honesty and calibration are not established; no zero-error physical accuracy claim.",
        },
        "MEASUREMENT-0.3-validity-and-missingness": {
            "validity": "Exact method/interpreter, source bindings, step coverage and state digests; non-boolean integer metrics in the declared bounds.",
            "missingness": "Unavailable execution yields UNKNOWN in certificate recheck; malformed captures refute, never fill missing metrics with zero.",
            "freshness": "New challenge and execution per invocation; no historical-record correspondence or wall-age guarantee.",
            "provenance": "Closed checked source bytes compile in the worker; parent rechecks loaded manifest and current sources, not a collector signature.",
        },
        "SENSOR-0.1-acquisition-and-observations": {
            "acquisition": "Isolated CPython transition execution with per-step thread clock and allocation tracer acquisition.",
            "phenomena": "Executing-thread CPU interval and traced Python allocation peak within that transition.",
            "measurements": "Indexed input/output state digests, thread_cpu_ns and traced_peak_bytes, with run identity.",
            "deployment": "Local source-loaded subprocess under the invoking host; not hostile-host isolation or an external physical transducer.",
        },
        "SENSOR-0.2-calibration-and-envelope": {
            "calibration_applicability": "Physical metrology calibration is outside the declared software-counter interpretation claim; any accuracy or external phenomenon claim needs additional evidence.",
            "calibration_evidence": "Controlled instrument inputs check software arithmetic and interval placement, not OS clock accuracy or tracer completeness.",
            "operating_range": "CPython finite replay bounds: at most 100000 operations and 4096 items; accepted nonnegative metrics through 2**63-1.",
            "drift": "Exact implementation and interpreter bindings detect changed selections; numerical clock drift is neither measured nor certified.",
        },
        "SENSOR-0.3-sampling-and-faults": {
            "sampling": "One before/after thread-clock pair and allocation peak per transition; replay validation precedes tracing.",
            "latency": "Selected subprocess timeout is 15 seconds; no real-time delivery guarantee.",
            "fault_detection": "Clock, transition, tracer, process and binding failures cannot produce a validated complete capture.",
            "recovery": "Finally stops tracing after started acquisition; another recheck starts a new process. No in-place repair or failover claim.",
        },
    }
    bindings = {
        name: {"reason": reason, "evidence": evidence, "declaration": answers}
        for name, answers in declarations.items()
    }
    for name, binding in bindings.items():
        previous = row["obligations"].get(name)
        if _review_binding_conflicts(
            previous, binding, refresh_reviewed=refresh_reviewed
        ):
            raise ValueError("PACKAGE_MIGRATION_MEASUREMENT_DECLARATION_CONFLICT")
    selected = {
        "object_id": row["object_id"],
        "mechanism": execution.ADAPTER,
        "reason": reason,
        "evidence": evidence,
    }
    checks = namespace.get("execution_checks", [])
    staged_checks = deepcopy(checks)
    _upsert_execution_check(
        staged_checks, selected, refresh_reviewed=refresh_reviewed
    )
    # Validate every existing decision before writing either role.
    for kind in ("MEASUREMENT", "SENSOR"):
        row["classification"][kind] = deepcopy(decision)
        if row.get("kind") != kind and kind not in row["specializations"]:
            row["specializations"].append(kind)
    row["obligations"].update(bindings)
    namespace.setdefault("execution_checks", [])[:] = staged_checks


def _select_token_asset(
    root: Path,
    namespace: dict,
    row: dict,
    files: dict[str, str],
    *,
    refresh_reviewed: bool = False,
) -> None:
    """Bind the reviewed token implementation to finite ASSET behavior."""
    from verifier.runtime import token_asset_execution as execution

    if row.get("object_id") != "vstd-token":
        raise ValueError("PACKAGE_MIGRATION_ASSET_OWNER_DIFFERS")
    path = execution.IMPLEMENTATION
    installed = Path(execution.__file__).parents[1] / path.removeprefix(
        "src/verifier/"
    )
    if (files.get(path) != bytes_digest(installed.read_bytes())
            or "file:" + path not in row.get("surfaces", [])):
        raise ValueError("PACKAGE_MIGRATION_ASSET_IMPLEMENTATION_DIFFERS")
    reviewed = _canonical_review_selection(
        root, row, files, package_original_review_computation, "ASSET",
        "PACKAGE_MIGRATION_ASSET", refresh_reviewed=refresh_reviewed,
    )
    owned_paths = package_original_review_computation.review_document()[
        "vstd-token"
    ]["owned_paths"]
    evidence = [{"path": owned, "sha256": files[owned]}
                for owned in owned_paths]
    reason = (
        "The reviewed TOKEN implementation owns the retained capability records "
        "used by this finite ASSET replay. Authority, real custody, redemption, "
        "supply conservation and backing remain NOT_ESTABLISHED."
    )
    selected = {"object_id": row["object_id"], "mechanism": execution.ADAPTER,
                "reason": reason, "evidence": evidence}
    checks = namespace.setdefault("execution_checks", [])
    staged_checks = deepcopy(checks)
    _upsert_execution_check(
        staged_checks, selected, refresh_reviewed=refresh_reviewed
    )
    row["classification"]["ASSET"] = reviewed["decision"]
    row["obligations"].update(reviewed["bindings"])
    if row.get("kind") != "ASSET" and "ASSET" not in row["specializations"]:
        row["specializations"].append("ASSET")
    checks[:] = staged_checks


def _select_emulator_control(
    root: Path,
    namespace: dict,
    row: dict,
    files: dict[str, str],
    *,
    refresh_reviewed: bool = False,
) -> None:
    """Bind one software emulator to both control roles without physical claims."""
    from verifier.runtime import emulator_control_execution as execution

    if row.get("object_id") != "vstd-firmware-emulator-accounting":
        raise ValueError("PACKAGE_MIGRATION_EMULATOR_CONTROL_OWNER_DIFFERS")
    path = execution.IMPLEMENTATION
    installed = Path(execution.__file__).parents[1] / path.removeprefix(
        "src/verifier/"
    )
    if (files.get(path) != bytes_digest(installed.read_bytes())
            or "file:" + path not in row.get("surfaces", [])):
        raise ValueError("PACKAGE_MIGRATION_EMULATOR_CONTROL_IMPLEMENTATION_DIFFERS")
    reviewed = {
        kind: _canonical_review_selection(
            root, row, files, package_semantic_review_records, kind,
            "PACKAGE_MIGRATION_EMULATOR_CONTROL",
            refresh_reviewed=refresh_reviewed,
        )
        for kind in ("CONTROLLER", "ACTUATOR")
    }
    evidence = [{"path": path, "sha256": files[path]}]
    reason = (
        "The reviewed reference emulator implements finite software controller "
        "and actuator transitions. TEST_HMAC_FIXTURE, typed simulated feedback "
        "and rollback checks do not establish physical actuation, calibration, "
        "stability, attestation or a physical safe state."
    )
    selected = {"object_id": row["object_id"], "mechanism": execution.ADAPTER,
                "reason": reason, "evidence": evidence}
    checks = namespace.setdefault("execution_checks", [])
    staged_checks = deepcopy(checks)
    _upsert_execution_check(
        staged_checks, selected, refresh_reviewed=refresh_reviewed
    )
    for kind, selection in reviewed.items():
        row["classification"][kind] = selection["decision"]
        row["obligations"].update(selection["bindings"])
        if row.get("kind") != kind and kind not in row["specializations"]:
            row["specializations"].append(kind)
    checks[:] = staged_checks


def _capture_source_inventory(root: Path) -> dict:
    """Capture the exact current candidate bytes that decided evidence binds to.

    Every call captures afresh: no manifest coordinate or earlier census is
    reused, and a refused or unreadable census yields no inventory rather than
    an empty one that would bind nothing.
    """
    try:
        census = self_polish_estate.capture_candidate_source_census(root)
        inventory = {row["path"]: row["sha256"] for row in census["files"]}
        census_digest = census["census_digest"]
    except (OSError, KeyError, TypeError, ValueError) as exc:
        code = (
            str(exc)
            if isinstance(exc, self_polish_estate.EstateError)
            else type(exc).__name__
        )
        return {
            "inventory": None,
            "census_digest": None,
            "unavailable": "PACKAGE_MIGRATION_SOURCE_INVENTORY_UNAVAILABLE:" + code,
        }
    return {
        "inventory": inventory,
        "census_digest": census_digest,
        "unavailable": None,
    }


def _bind_source_inventory(opening: dict, closing: dict) -> dict:
    """Decide whether the opening census still describes the bytes that were read.

    Only BOUND lets decided evidence bind.  Its inventory is the opening capture,
    which the closing capture shows unchanged across generation.
    """
    if opening["unavailable"] is not None:
        status = "UNAVAILABLE"
    elif closing["unavailable"] is not None:
        status = "CLOSING_UNAVAILABLE"
    elif closing["census_digest"] != opening["census_digest"]:
        status = "MUTATED"
    else:
        status = "BOUND"
    return {
        "status": status,
        "opening_census_digest": opening["census_digest"],
        "closing_census_digest": closing["census_digest"],
        "unavailable": opening["unavailable"] or closing["unavailable"],
        "inventory": opening["inventory"] if status == "BOUND" else None,
    }


def _public_source_binding(binding: dict | None) -> dict:
    """Report the binding's status and digests without the inventory bytes."""
    if binding is None:
        return {
            "status": "ABSENT",
            "opening_census_digest": None,
            "closing_census_digest": None,
            "unavailable": None,
        }
    return {key: value for key, value in binding.items() if key != "inventory"}


def _unknown_original_kind_closure(diagnostic: str) -> dict:
    """Return the bounded UNKNOWN closure for a denominator that cannot bind.

    No per-cell list is emitted: an unbound or refused input is not a decided
    gap, so it must not be counted as one.
    """
    question_count = package_original_kind_catalog.ORIGINAL_KIND_QUESTION_DENOMINATOR
    return {
        "status": "UNKNOWN",
        "question_count": question_count,
        "decided_count": 0,
        "unresolved_count": question_count,
        "unresolved": [],
        "next_unresolved": None,
        "diagnostic": diagnostic,
    }


def _original_kind_closure(
    row_index: dict,
    *,
    root: str | Path | None,
    exact_rows: bool,
    source_binding: dict | None,
) -> tuple[dict, list[dict]]:
    """Assess original-kind cells against one bound source inventory, or fail UNKNOWN.

    Any input that cannot bind the exact denominator (catalog refusal, object
    denominator drift, absent or non-BOUND inventory) yields UNKNOWN without
    enumerating cells.  Only a closure computed against the bound inventory
    contributes its exact unresolved coordinates.
    """
    expected_object_count = (
        package_original_kind_catalog.ORIGINAL_KIND_QUESTION_DENOMINATOR
        // len(package_original_kind_catalog.ORIGINAL_NON_OBJECT_KINDS)
    )
    if not exact_rows or len(row_index) != expected_object_count:
        return (
            _unknown_original_kind_closure(
                "PACKAGE_ORIGINAL_KIND_CATALOG_OBJECT_DENOMINATOR_DIFFERS:"
                + str(len(row_index))
            ),
            [],
        )
    inventory = None if source_binding is None else source_binding.get("inventory")
    if inventory is None:
        status = "ABSENT" if source_binding is None else source_binding["status"]
        return (
            _unknown_original_kind_closure(
                "PACKAGE_ORIGINAL_KIND_SOURCE_INVENTORY_" + status
            ),
            [],
        )
    if root is None:
        return (
            _unknown_original_kind_closure(
                "PACKAGE_ORIGINAL_KIND_CATALOG_VALIDATED_ROOT_ABSENT"
            ),
            [],
        )
    try:
        closure = package_original_kind_catalog.admission_closure_report(
            row_index, root=root, source_inventory=inventory
        )
    except (OSError, ValueError) as exc:
        return (
            _unknown_original_kind_closure(
                "PACKAGE_ORIGINAL_KIND_CATALOG_REFUSED:" + str(exc)
            ),
            [],
        )
    return closure, list(closure["unresolved"])


def _review_gap_report(
    document: dict,
    *,
    root: str | Path | None = None,
    source_binding: dict | None = None,
) -> dict:
    """Expose exact remaining Tier-0 questions without claiming admission.

    ``source_binding`` is the migration's opening/closing census binding; decided
    original-kind evidence binds only when it is BOUND.  A compact version-6
    namespace carries evidence as digest selectors, so it is expanded first: a
    selector is never evidence itself.
    """
    review_gaps = []
    incomplete_obligations = []
    unowned_evidence = []
    namespace = document["namespace"]
    if (
        type(namespace) is dict
        and namespace.get("schema_version") == namespace_manifest.COMPACT_SCHEMA
    ):
        namespace = namespace_manifest.normalize_manifest(namespace)
    object_rows = namespace["objects"]
    for row in object_rows:
        owned_paths = {
            surface.removeprefix("file:")
            for surface in row["surfaces"]
            if surface.startswith("file:")
        }
        for kind, decision in row["classification"].items():
            if decision["status"] == "UNRESOLVED":
                review_gaps.append({"object_id": row["object_id"], "kind": kind})
            for reference in decision["evidence"]:
                if reference["path"] not in owned_paths:
                    unowned_evidence.append(
                        {
                            "object_id": row["object_id"],
                            "binding": "classification:" + kind,
                            "path": reference["path"],
                        }
                    )
        for obligation_id, binding in row["obligations"].items():
            if (
                not binding["reason"].strip()
                or not binding["evidence"]
                or not binding["declaration"]
                or not all(value.strip() for value in binding["declaration"].values())
            ):
                incomplete_obligations.append(
                    {"object_id": row["object_id"], "obligation_id": obligation_id}
                )
            for reference in binding["evidence"]:
                if reference["path"] not in owned_paths:
                    unowned_evidence.append(
                        {
                            "object_id": row["object_id"],
                            "binding": "obligation:" + obligation_id,
                            "path": reference["path"],
                        }
                    )
    row_index = {
        row["object_id"]: row
        for row in object_rows
        if type(row) is dict and type(row.get("object_id")) is str
    }
    original_kind_closure, original_kind_gaps = _original_kind_closure(
        row_index,
        root=root,
        exact_rows=len(row_index) == len(object_rows),
        source_binding=source_binding,
    )
    present = {(item["object_id"], item["kind"]) for item in review_gaps}
    for item in original_kind_gaps:
        coordinate = (item["object_id"], item["kind"])
        if coordinate not in present:
            review_gaps.append(dict(item))
            present.add(coordinate)
    status = (
        "FAIL"
        if unowned_evidence
        else "UNKNOWN"
        if (
            review_gaps
            or incomplete_obligations
            or original_kind_closure["status"] != "PASS"
        )
        else "PASS"
    )
    return {
        "status": status,
        "unresolved_decision_count": len(review_gaps),
        "unresolved_decisions": review_gaps,
        "incomplete_obligation_count": len(incomplete_obligations),
        "incomplete_obligations": incomplete_obligations,
        "unowned_evidence_count": len(unowned_evidence),
        "unowned_evidence": unowned_evidence,
        "original_kind_closure": original_kind_closure,
        "source_binding": _public_source_binding(source_binding),
    }


def _review_gap_summary(gaps: list[dict[str, Any]]) -> dict[str, Any]:
    """Count recorded review gaps by kind and keep each one for the developer."""
    by_gap: dict[str, int] = {}
    for gap in gaps:
        by_gap[gap["gap"]] = by_gap.get(gap["gap"], 0) + 1
    return {"count": len(gaps), "by_gap": dict(sorted(by_gap.items())), "items": gaps}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--backup", type=Path)
    parser.add_argument(
        "--refresh-unresolved",
        action="store_true",
        help="Rebind only unanswered questions to current bytes; preserve all decided evidence.",
    )
    parser.add_argument(
        "--refresh-reviewed",
        action="store_true",
        help="Explicitly reapply selected source-review catalogs to current bytes while preserving all bindings outside their exact key sets.",
    )
    parser.add_argument(
        "--select-manifest-publication",
        action="store_true",
        help="Select the exact installed private-file experiment for the named manifest writer; never replace an existing selection.",
    )
    parser.add_argument(
        "--select-worker-protocol",
        action="store_true",
        help="Add the reviewed dispatcher PROTOCOL role and its exact private execution; refuse conflicting prior decisions.",
    )
    parser.add_argument(
        "--select-provenance-policy",
        action="store_true",
        help="Add the reviewed owned provenance POLICY role and its finite execution; preserve other roles and refuse conflicting evidence.",
    )
    parser.add_argument(
        "--select-resource-measurement",
        action="store_true",
        help="Add source-reviewed MEASUREMENT and SENSOR roles to the actual fresh SIM meter; never imply physical calibration.",
    )
    parser.add_argument(
        "--select-token-asset",
        action="store_true",
        help="Select the reviewed TOKEN implementation for bounded ASSET replay; never imply authority, custody, redemption or backing.",
    )
    parser.add_argument(
        "--select-emulator-control",
        action="store_true",
        help="Select the reviewed emulator for bounded CONTROLLER and ACTUATOR replay; never imply a physical effect or safe state.",
    )
    parser.add_argument(
        "--select-harness-financial-classification",
        action="store_true",
        help="Apply the reviewed HARNESS LEDGER refutation and TRANSACTION boundary; refuse conflicting prior answers.",
    )
    parser.add_argument(
        "--select-harness-launch-profile",
        action="store_true",
        help="Bootstrap the reviewed HARNESS launch denominator into its manifest payload; later source-only rebinding is automatic.",
    )
    parser.add_argument(
        "--advance-harness-launch-profile",
        action="store_true",
        help="Explicitly replace a selected HARNESS launch review from the exact current frozen catalog; requires --select-harness-launch-profile and --refresh-reviewed.",
    )
    parser.add_argument(
        "--select-source-refresh-binding",
        action="store_true",
        help="Bind the complete non-manifest source census in the current GRAPH so unchanged polish preflight avoids full remigration.",
    )
    parser.add_argument(
        "--select-source-semantic-profile",
        action="store_true",
        help="Bind reviewed answers to location-free Python ASTs and byte-exact other-language sources; later semantic changes require focused review.",
    )
    parser.add_argument(
        "--select-package-namespace-review",
        action="store_true",
        help="Apply the complete source-bound Tier-0 review for the five existing reviewed objects and all installed semantic child objects.",
    )
    parser.add_argument(
        "--select-compiled-consequence-graph",
        action="store_true",
        help="Compile typed external-effect declarations only from exact reviewed ROBOT/FINBOT APPLIES evidence; requires --refresh-reviewed.",
    )
    parser.add_argument(
        "--install-semantic-ownership",
        action="store_true",
        help="Add the audited path-disjoint consequential child objects; ordinary reruns preserve an installed complete catalog.",
    )
    parser.add_argument(
        "--replace-structural-instance-checks",
        action="store_true",
        help="Replace only historical structural certificate selections with the fresh current-package facet replay; retain all nonstructural selections and evidence files.",
    )
    parser.add_argument(
        "--retire-package-graph-instance-check",
        action="store_true",
        help="Retire only the package-root GRAPH-3.1 artifact selection after the exact enriched root, source bindings, and refreshed owned-source representation update prove the fresh adapter basis; leave every artifact file and other selection untouched.",
    )
    parser.add_argument(
        "--record-review-gaps",
        action="store_true",
        help="Record, rather than refuse, review gaps (an unsupported label, paths added after review, a stale reopened answer); unanswered questions stay unanswered and each gap is listed in the report.",
    )
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    target = root / "objects.vstd"
    opening_inventory = _capture_source_inventory(root)
    before, document = namespace_manifest.read_manifest(target)
    review_gaps: list[dict[str, Any]] = []
    migrated = migrate(
        root,
        document,
        record_review_gaps=args.record_review_gaps,
        review_gaps=review_gaps,
        refresh_unresolved=args.refresh_unresolved,
        refresh_reviewed=args.refresh_reviewed,
        select_manifest_publication=args.select_manifest_publication,
        select_worker_protocol=args.select_worker_protocol,
        select_provenance_policy=args.select_provenance_policy,
        select_resource_measurement=args.select_resource_measurement,
        select_token_asset=args.select_token_asset,
        select_emulator_control=args.select_emulator_control,
        select_harness_financial_classification=args.select_harness_financial_classification,
        select_harness_launch_profile=args.select_harness_launch_profile,
        advance_harness_launch_profile=args.advance_harness_launch_profile,
        select_source_refresh_binding=args.select_source_refresh_binding,
        select_source_semantic_profile=args.select_source_semantic_profile,
        select_package_namespace_review=args.select_package_namespace_review,
        select_compiled_consequence_graph=args.select_compiled_consequence_graph,
        install_semantic_ownership=args.install_semantic_ownership,
        replace_structural_instance_checks=args.replace_structural_instance_checks,
        retire_package_graph_instance_check=args.retire_package_graph_instance_check,
    )
    after = canonical_bytes(migrated) + b"\n"
    tier_zero_manifest._strict_json_document(after)
    source_binding = _bind_source_inventory(
        opening_inventory, _capture_source_inventory(root)
    )
    if args.write and source_binding["status"] != "BOUND":
        raise ValueError(
            "PACKAGE_MIGRATION_SOURCE_INVENTORY_" + source_binding["status"]
        )
    if args.write:
        if args.backup is None:
            parser.error("--write requires --backup outside the selected repository")
        backup = args.backup.parent.resolve(strict=True) / args.backup.name
        if backup == root or root in backup.parents or not backup.parent.is_dir():
            parser.error("backup must have an existing parent outside the repository")
        with backup.open("xb") as stream:
            stream.write(before)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=root, prefix=".vstd-migration-", delete=False
            ) as stream:
                temporary = Path(stream.name)
                stream.write(after)
            try:
                current = namespace_manifest.read_manifest(target)[0]
            except (OSError, ValueError) as exc:
                raise ValueError("PACKAGE_MIGRATION_CONCURRENT_CHANGE") from exc
            if current != before:
                raise ValueError("PACKAGE_MIGRATION_CONCURRENT_CHANGE")
            os.replace(temporary, target)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()  # Only this invocation's unpublished file.
    review_report = _review_gap_report(
        migrated, root=root, source_binding=source_binding
    )
    print(
        json.dumps(
            {
                "status": "MIGRATED_DRAFT" if args.write else "PREVIEW",
                "before_digest": bytes_digest(before),
                "after_digest": bytes_digest(after),
                "bytes": len(after),
                "objects": [
                    {
                        "id": row["object_id"],
                        "kind": row["kind"],
                        "surfaces": len(row["surfaces"]),
                    }
                    for row in migrated["namespace"]["objects"]
                ],
                "slot_count": migrated["obligation_denominator"]["slot_count"],
                "route_count": migrated["obligation_denominator"]["route_count"],
                "tier_zero_review": review_report,
                "review_gaps": _review_gap_summary(review_gaps),
                "instance_check_transition": _instance_check_transition(
                    document, migrated
                ),
                "claim_boundary": "Migration is not admission. Applicability, declarations and discovery gaps must be resolved.",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
