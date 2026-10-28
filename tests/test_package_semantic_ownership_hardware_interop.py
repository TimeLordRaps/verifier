from __future__ import annotations

import hashlib
from pathlib import Path

from verifier.runtime.package_semantic_ownership_hardware_interop import (
    HARDWARE_INTEROP_OWNERSHIP_SPECS,
)


ROOT = Path(__file__).parents[1]

# Each value is primary kind, accumulated roles, fixed operands, and owned paths.
# This is intentionally independent of the catalog rows so drift in any semantic
# field or path denominator is visible in one focused review.
EXPECTED = {
    "vstd-hardware-public-api": (
        "HARDWARE", (), (),
        ("src/verifier/hardware/__init__.py", "src/verifier/hardware/adapters/__init__.py"),
    ),
    "vstd-generic-accelerator-evidence-sensor": (
        "SENSOR", ("MEASUREMENT",), (),
        (
            "src/verifier/hardware/adapters/base.py",
            "src/verifier/hardware/adapters/generic.py",
            "src/verifier/hardware/adapters/intel.py",
        ),
    ),
    "vstd-provider-control-plane-evidence-protocol": (
        "PROTOCOL", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        (
            "src/verifier/hardware/adapters/provider.py",
            "src/verifier/hardware/provider_evidence.py",
        ),
    ),
    "vstd-hardware-evidence-records": (
        "RECEIPT", ("ASSET", "LEDGER", "MEASUREMENT", "POLICY", "PROTOCOL"),
        (("hardware", ("vstd-hardware",)), ("subject", ("vstd-hardware",))),
        (
            "src/verifier/hardware/canonical.py",
            "src/verifier/hardware/models.py",
            "src/verifier/hardware/schema.py",
        ),
    ),
    "vstd-hardware-attestation-verifier": (
        "VERIFIER", ("POLICY", "PROTOCOL"), (),
        ("src/verifier/hardware/attestation.py",),
    ),
    "vstd-hardware-claim-conformance-policy": (
        "POLICY", (), (),
        ("src/verifier/hardware/claims.py", "src/verifier/hardware/conformance.py"),
    ),
    "vstd-hardware-accounting-continuity-ledger": (
        "LEDGER", ("POLICY",), (),
        ("src/verifier/hardware/continuity.py",),
    ),
    "vstd-hardware-provenance-graph-attachment": (
        "TRANSACTION", ("ASSET", "MEASUREMENT", "POLICY"), (),
        ("src/verifier/hardware/provenance.py",),
    ),
    "vstd-accelerator-profile-registry": (
        "DATA", (
            "ACTUATOR", "ASSET", "CONTROLLER", "FINBOT", "LEDGER", "MARKET",
            "MEASUREMENT", "POLICY", "PROTOCOL", "ROBOT", "SENSOR", "TRANSACTION",
        ), (),
        ("src/verifier/hardware/registry.py",),
    ),
    "vstd-temporal-comb-measurement": (
        "MEASUREMENT", ("POLICY",), (),
        ("src/verifier/hardware/time_comb.py",),
    ),
    "vstd-artifact-trace-protocol": (
        "PROTOCOL", ("ACTUATOR", "MEASUREMENT", "POLICY", "SENSOR", "TRANSACTION"), (),
        ("src/verifier/hardware/tracers.py",),
    ),
    "vstd-hardware-receipt-validator": (
        "VERIFIER", ("POLICY",), (),
        ("src/verifier/hardware/validation.py",),
    ),
    "vstd-interoperability-public-api": (
        "VERIFIER", (), (),
        ("src/verifier/interoperability/__init__.py",),
    ),
    "vstd-interoperability-component-catalog": (
        "DATA", ("POLICY",), (),
        (
            "src/verifier/interoperability/catalog.py",
            "src/verifier/interoperability/reference_catalog.py",
        ),
    ),
    "vstd-component-index-storage": (
        "DATA", ("MEASUREMENT", "POLICY", "SENSOR", "TRANSACTION"), (),
        ("src/verifier/interoperability/component_index.py",),
    ),
    "vstd-interoperability-validation-planning-policy": (
        "POLICY", (), (),
        (
            "src/verifier/interoperability/control_surface.py",
            "src/verifier/interoperability/execution_readiness.py",
        ),
    ),
    "vstd-selected-digest-verifier": (
        "VERIFIER", ("POLICY",), (),
        ("src/verifier/interoperability/selected_execution.py",),
    ),
    "vstd-authority-composition-verifier": (
        "VERIFIER", ("POLICY", "PROTOCOL"), (),
        ("src/verifier/interoperability/authority_composition.py",),
    ),
    "vstd-silo-composition-qualification": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR"), (),
        ("src/verifier/interoperability/composition_qualification.py",),
    ),
    "vstd-typed-formation-wire-protocol": (
        "PROTOCOL", ("POLICY",), (),
        ("src/verifier/interoperability/formation_wire.py",),
    ),
    "vstd-typed-formation-certificate-producer": (
        "VERIFIER", ("POLICY",), (),
        ("src/verifier/interoperability/formation_producer.py",),
    ),
    "vstd-typed-formation-checker": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        (
            "src/verifier/interoperability/formation_checker.py",
            "src/verifier/interoperability/formation_mechanism.py",
        ),
    ),
    "vstd-typed-formation-receipt": (
        "RECEIPT", ("POLICY",),
        (("hardware", ("vstd-hardware",)), ("subject", ("vstd-package-object",))),
        (
            "src/verifier/interoperability/formation_receipt.py",
            "src/verifier/interoperability/formation_storage.py",
        ),
    ),
    "vstd-source-grounding-verifier": (
        "VERIFIER", ("POLICY",), (),
        ("src/verifier/interoperability/source_grounding.py",),
    ),
    "vstd-relation-boundary-verifier": (
        "VERIFIER", ("POLICY",), (),
        ("src/verifier/interoperability/relation_boundary.py",),
    ),
    "vstd-bounded-completeness-verifier": (
        "VERIFIER", ("POLICY",), (),
        ("src/verifier/interoperability/bounded_completeness.py",),
    ),
    "vstd-proposition-transfer-verifier": (
        "VERIFIER", ("POLICY",), (),
        ("src/verifier/interoperability/proposition_transfer.py",),
    ),
    "vstd-geometry-consistency-verifier": (
        "VERIFIER", ("POLICY",), (),
        (
            "src/verifier/interoperability/geometry_conflicts.py",
            "src/verifier/interoperability/geometry_constraints.py",
        ),
    ),
    "vstd-graph-topology-verifier": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/interoperability/graph_topology.py",),
    ),
    "vstd-global-cycle-verifier": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/interoperability/global_cycle_assessment.py",),
    ),
    "vstd-runtime-authority-correspondence": (
        "VERIFIER",
        ("ACTUATOR", "LEDGER", "MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR", "TRANSACTION"),
        (),
        ("src/verifier/interoperability/runtime_authority_correspondence.py",),
    ),
    "vstd-untraversability-verifier": (
        "VERIFIER", ("ACTUATOR", "CONTROLLER", "MEASUREMENT", "POLICY", "SENSOR", "TRANSACTION"), (),
        ("src/verifier/interoperability/untraversable.py",),
    ),
}


def _sha256(lines: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()


def test_partition_pins_all_semantics_and_exact_paths() -> None:
    actual = {
        item.object_id: (
            item.primary_kind,
            item.specializations,
            item.operands,
            item.owned_paths,
        )
        for item in HARDWARE_INTEROP_OWNERSHIP_SPECS
    }
    assert actual == EXPECTED
    assert len(actual) == 32

    paths = [
        path
        for item in HARDWARE_INTEROP_OWNERSHIP_SPECS
        for path in item.owned_paths
    ]
    assert len(paths) == 44
    assert len(paths) == len(set(paths))
    assert all((ROOT / path).is_file() for path in paths)
    assert all(item.representation_role.strip() for item in HARDWARE_INTEROP_OWNERSHIP_SPECS)
    assert all(item.necessity_reason.strip() for item in HARDWARE_INTEROP_OWNERSHIP_SPECS)
    assert all(item.consequence_boundary.strip() for item in HARDWARE_INTEROP_OWNERSHIP_SPECS)


def test_partition_has_no_unreviewed_endpoint_or_generic_object_escape() -> None:
    for item in HARDWARE_INTEROP_OWNERSHIP_SPECS:
        kinds = (item.primary_kind, *item.specializations)
        assert "OBJECT" not in kinds
        endpoint_kinds = {"ROBOT", "FINBOT", "MARKET"}.intersection(kinds)
        if item.object_id == "vstd-accelerator-profile-registry":
            assert endpoint_kinds == {"ROBOT", "FINBOT", "MARKET"}
        else:
            assert not endpoint_kinds


def test_partition_pins_audit_digests() -> None:
    paths = [
        path
        for item in HARDWARE_INTEROP_OWNERSHIP_SPECS
        for path in item.owned_paths
    ]
    assert _sha256(paths) == "0325fc23e3eba4ce7043a2deef80debfdcbb5e241ceb5f8af5e5f32d7735d46c"

    mapping = [
        f"{item.object_id}\t{path}"
        for item in HARDWARE_INTEROP_OWNERSHIP_SPECS
        for path in item.owned_paths
    ]
    assert _sha256(mapping) == "9b9f8c8d90945ed280b4f8b30c8a1d3b43617ccdfd3d06e13562b76ae3f0b743"

    inventory = []
    for path in paths:
        content = (ROOT / path).read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        inventory.append(f"{path}\t{len(content)}\t{digest}")
    assert _sha256(inventory) == "e74f665b6fbc6aa968c02ab136c09ffeff50d6228c001dd8ad1ccb23c772a6ea"
