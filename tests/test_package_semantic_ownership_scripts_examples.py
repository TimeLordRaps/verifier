from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path

from verifier.runtime.package_semantic_ownership import (
    SEMANTIC_OWNERSHIP_SPECS,
    validate_catalog,
)
from verifier.runtime.package_semantic_ownership_scripts_examples import (
    SCRIPT_EXAMPLE_OWNERSHIP_SPECS,
)
from verifier.runtime.namespace_contracts import namespace_registry


ROOT = Path(__file__).parents[1]
EXECUTION_ROLES = (
    "ACTUATOR",
    "MEASUREMENT",
    "POLICY",
    "PROTOCOL",
    "SENSOR",
    "TRANSACTION",
)
EXPECTED_REVIEWED_SOURCE_DRIFT = {
    "scripts/check_namespace_closure.py": (
        "7a86dbb7528e0446ea49a6b024521b627f59fcba2f7466ab82e18668b4fef37c",
        "vstd-public-source-policy-gates",
        "VERIFIER",
        EXECUTION_ROLES,
        (("HARNESS", "APPLIES"),),
    ),
    "scripts/preflight.py": (
        "8f1335c085a855ed020fe7cffcb14fead4ebd7eb0d5a9c311720aa4504dabe0d",
        "vstd-local-preflight-controller",
        "CONTROLLER",
        EXECUTION_ROLES,
        (("ENV", "APPLIES"), ("HARNESS", "APPLIES"), ("VERIFIER", "APPLIES")),
    ),
    "scripts/release_artifacts.py": (
        "804a8d7b98402678b620ecb3b54159585de561ae5398be18607f55eff489715e",
        "vstd-release-artifact-controller",
        "CONTROLLER",
        EXECUTION_ROLES,
        (("ENV", "APPLIES"), ("HARNESS", "APPLIES"), ("VERIFIER", "APPLIES")),
    ),
    "src/verifier/runtime/package_manifest_migration.py": (
        "47b1841af755a9a562b73713d4a90d65f58e9d5ec9bdec5b82b68d63bff682d0",
        "vstd-package-manifest-migration-controller",
        "CONTROLLER",
        EXECUTION_ROLES,
        (
            ("ENV", "APPLIES"),
            ("RECEIPT", "APPLIES"),
            ("VERIFIER", "APPLIES"),
        ),
    ),
    "src/verifier/runtime/package_manifest_refresh.py": (
        "b20ffe5d656f1f237607995d8baf57b1634e0e56a27bc7a605ee6111b3174e4d",
        "vstd-package-manifest-migration-controller",
        "CONTROLLER",
        EXECUTION_ROLES,
        (
            ("ENV", "APPLIES"),
            ("RECEIPT", "APPLIES"),
            ("VERIFIER", "APPLIES"),
        ),
    ),
}


def _sha256(lines: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()


def test_partition_is_an_exact_real_path_partition() -> None:
    validated = validate_catalog(ROOT, SCRIPT_EXAMPLE_OWNERSHIP_SPECS)
    assert validated == tuple(
        sorted(SCRIPT_EXAMPLE_OWNERSHIP_SPECS, key=lambda item: item.object_id)
    )
    assert len(validated) == 55

    paths = [path for item in validated for path in item.owned_paths]
    assert len(paths) == 175
    assert len(paths) == len(set(paths))
    assert sum(path.startswith("scripts/") for path in paths) == 40
    assert sum(path.startswith("examples/") for path in paths) == 133
    assert sum(path.startswith("src/verifier/runtime/") for path in paths) == 2
    assert all(
        path.startswith(("scripts/", "examples/", "src/verifier/runtime/"))
        for path in paths
    )
    assert all((ROOT / path).is_file() for path in paths)


def test_partition_does_not_overlap_another_authoritative_owner() -> None:
    ids = {item.object_id for item in SCRIPT_EXAMPLE_OWNERSHIP_SPECS}
    paths = {
        path for item in SCRIPT_EXAMPLE_OWNERSHIP_SPECS for path in item.owned_paths
    }
    other_ids = {
        item.object_id for item in SEMANTIC_OWNERSHIP_SPECS if item.object_id not in ids
    }
    other_paths = {
        path
        for item in SEMANTIC_OWNERSHIP_SPECS
        if item.object_id not in ids
        for path in item.owned_paths
    }
    assert ids.isdisjoint(other_ids)
    assert paths.isdisjoint(other_paths)


def test_partition_has_reasons_and_no_generic_or_consequential_escape() -> None:
    by_id = {item.object_id: item for item in SCRIPT_EXAMPLE_OWNERSHIP_SPECS}
    for item in SCRIPT_EXAMPLE_OWNERSHIP_SPECS:
        kinds = (item.primary_kind, *item.specializations)
        assert "OBJECT" not in kinds
        assert "BOT" not in kinds
        assert "ROBOT" not in kinds
        assert "FINBOT" not in kinds
        assert "MARKET" not in kinds
        assert item.representation_role.strip()
        assert item.necessity_reason.strip()
        assert item.consequence_boundary.strip()
        assert not item.operands

    registry = namespace_registry()
    assert all(
        registry[kind].extends is not None
        for item in SCRIPT_EXAMPLE_OWNERSHIP_SPECS
        for kind in item.specializations
    )
    ledger_owners = {
        item.object_id
        for item in SCRIPT_EXAMPLE_OWNERSHIP_SPECS
        if "LEDGER" in (item.primary_kind, *item.specializations)
    }
    assert ledger_owners == {
        "vstd-artifact-network-fixture-ledger",
        "vstd-scitt-local-log-specimen",
    }
    assert by_id["vstd-logits-constraint-harness"].primary_kind == "HARNESS"
    assert by_id["vstd-zero-identity-fixture-corpus"].primary_kind == "DATA"
    assert by_id["vstd-zero-identity-policy"].primary_kind == "POLICY"
    assert by_id["vstd-zero-identity-reference-verifier"].primary_kind == "VERIFIER"
    assert by_id["vstd-zero-identity-status-model"].primary_kind == "POLICY"
    assert "trained or predictive MODEL" in by_id[
        "vstd-zero-identity-status-model"
    ].necessity_reason
    assert "no trained MODEL inference" in by_id[
        "vstd-logits-constraint-harness"
    ].consequence_boundary
    migration = by_id["vstd-package-manifest-migration-controller"]
    assert "not an accounting LEDGER" in migration.consequence_boundary
    assert "LEDGER" not in (migration.primary_kind, *migration.specializations)


def test_partition_pins_evidence_backed_cross_root_roles() -> None:
    decisions = {
        item.object_id: tuple(
            (decision.kind, decision.status) for decision in item.root_role_decisions
        )
        for item in SCRIPT_EXAMPLE_OWNERSHIP_SPECS
        if item.root_role_decisions
    }
    assert decisions == {
        "vstd-artifact-network-fixture-ledger": (("DATA", "APPLIES"), ("RECEIPT", "DOES_NOT_APPLY")),
        "vstd-documentation-site-assembly": (("ENV", "APPLIES"), ("HARNESS", "APPLIES")),
        "vstd-domain-grounding-specimen": (("AGENT", "APPLIES"), ("BENCH", "APPLIES"), ("BOT", "APPLIES"), ("DATA", "APPLIES"), ("ENV", "APPLIES"), ("HARDWARE", "APPLIES"), ("HARNESS", "APPLIES"), ("MODEL", "APPLIES"), ("SIM", "APPLIES"), ("TOKEN", "APPLIES"), ("TRAIN", "APPLIES")),
        "vstd-example-catalog-guide": (("HARNESS", "DOES_NOT_APPLY"),),
        "vstd-example-dataset-gate-verifier": (("DATA", "APPLIES"),),
        "vstd-example-gate-pipeline": (("DATA", "APPLIES"),),
        "vstd-experiment-index-materialization": (("VERIFIER", "APPLIES"),),
        "vstd-first-software-workflow-declarations": (("DATA", "APPLIES"),),
        "vstd-flagship-adversarial-receipts": (("RECEIPT", "DOES_NOT_APPLY"),),
        "vstd-graph-topology-specimen": (("GRAPH", "APPLIES"), ("HYPER", "APPLIES")),
        "vstd-interoperability-composition-harness": (("VERIFIER", "APPLIES"),),
        "vstd-local-preflight-controller": (("ENV", "APPLIES"), ("HARNESS", "APPLIES"), ("VERIFIER", "APPLIES")),
        "vstd-logits-constraint-harness": (("DATA", "APPLIES"), ("MODEL", "DOES_NOT_APPLY"), ("VERIFIER", "APPLIES")),
        "vstd-monograph-build-transaction": (("HARNESS", "APPLIES"),),
        "vstd-package-manifest-migration-controller": (("ENV", "APPLIES"), ("RECEIPT", "APPLIES"), ("VERIFIER", "APPLIES")),
        "vstd-platform-evidence-recording": (("ENV", "APPLIES"), ("RECEIPT", "DOES_NOT_APPLY")),
        "vstd-prdel-self-polish-declarations": (("DATA", "APPLIES"), ("HARNESS", "DOES_NOT_APPLY")),
        "vstd-prdel-source-selection-checks": (("HARNESS", "APPLIES"),),
        "vstd-public-reference-generation": (("ENV", "APPLIES"), ("HARNESS", "APPLIES"), ("VERIFIER", "APPLIES")),
        "vstd-public-source-policy-gates": (("HARNESS", "APPLIES"),),
        "vstd-publication-state-observers": (("VERIFIER", "APPLIES"),),
        "vstd-pull-request-promotion-policy": (("HARNESS", "APPLIES"),),
        "vstd-release-artifact-controller": (("ENV", "APPLIES"), ("HARNESS", "APPLIES"), ("VERIFIER", "APPLIES")),
        "vstd-risc0-proof-environment": (("DATA", "APPLIES"),),
        "vstd-risc0-proof-host-controller": (("HARNESS", "APPLIES"), ("RECEIPT", "APPLIES"), ("VERIFIER", "APPLIES")),
        "vstd-risc0-recorded-proof": (("RECEIPT", "APPLIES"),),
        "vstd-scitt-comparison-catalog-entry": (("RECEIPT", "DOES_NOT_APPLY"),),
        "vstd-scitt-distribution-fetch-controller": (("ENV", "APPLIES"), ("HARNESS", "APPLIES"), ("VERIFIER", "APPLIES")),
        "vstd-scitt-local-log-specimen": (("DATA", "APPLIES"), ("RECEIPT", "DOES_NOT_APPLY")),
        "vstd-scitt-native-comparison-plan": (("DATA", "APPLIES"),),
        "vstd-scitt-native-execution-harness": (("ENV", "APPLIES"), ("HARNESS", "APPLIES")),
        "vstd-scitt-native-package-marker": (("HARNESS", "DOES_NOT_APPLY"), ("RECEIPT", "DOES_NOT_APPLY"), ("VERIFIER", "DOES_NOT_APPLY")),
        "vstd-scitt-requirement-consistency-verifier": (("ENV", "APPLIES"),),
        "vstd-scitt-source-freeze-transaction": (("VERIFIER", "APPLIES"),),
        "vstd-selected-validation-guide": (("HARNESS", "DOES_NOT_APPLY"), ("VERIFIER", "DOES_NOT_APPLY")),
        "vstd-stored-component-export": (("HARNESS", "APPLIES"),),
        "vstd-verification-geometry-residual": (("GRAPH", "APPLIES"),),
        "vstd-workflow-verdict-neutrality-specimen": (("DATA", "APPLIES"), ("EVENT", "APPLIES")),
        "vstd-zero-identity-policy": (("IDENTITY", "DOES_NOT_APPLY"), ("RECEIPT", "DOES_NOT_APPLY")),
        "vstd-zero-identity-status-model": (("DATA", "APPLIES"), ("IDENTITY", "DOES_NOT_APPLY"), ("MODEL", "DOES_NOT_APPLY"), ("RECEIPT", "DOES_NOT_APPLY")),
        "vstd-zizk-reference-guide": (("IDENTITY", "DOES_NOT_APPLY"), ("RECEIPT", "DOES_NOT_APPLY")),
    }
    for item in SCRIPT_EXAMPLE_OWNERSHIP_SPECS:
        for decision in item.root_role_decisions:
            assert decision.reason.strip()


def test_reviewed_source_drift_keeps_exact_bytes_owner_and_accumulated_roles() -> None:
    owners_by_path = {
        path: item
        for item in SCRIPT_EXAMPLE_OWNERSHIP_SPECS
        for path in item.owned_paths
    }
    actual = {}
    for path in EXPECTED_REVIEWED_SOURCE_DRIFT:
        owner = owners_by_path[path]
        actual[path] = (
            hashlib.sha256((ROOT / path).read_bytes()).hexdigest(),
            owner.object_id,
            owner.primary_kind,
            owner.specializations,
            tuple(
                (decision.kind, decision.status)
                for decision in owner.root_role_decisions
            ),
        )

    assert actual == EXPECTED_REVIEWED_SOURCE_DRIFT


def test_partition_pins_mapping_semantics_and_current_source_inventory() -> None:
    paths = [
        path for item in SCRIPT_EXAMPLE_OWNERSHIP_SPECS for path in item.owned_paths
    ]
    assert _sha256(paths) == (
        "a236bdf03c1bf67568ebfea236a6431c1624d6faa9d094d3e031ce68cecf56f9"
    )

    mapping = [
        f"{item.object_id}\t{path}"
        for item in SCRIPT_EXAMPLE_OWNERSHIP_SPECS
        for path in item.owned_paths
    ]
    assert _sha256(mapping) == (
        "cfe540a8f7312da5dd9597b8ab7c318b6143c54a463f5efd9922b73e50ea8127"
    )

    semantic_bytes = json.dumps(
        [asdict(item) for item in SCRIPT_EXAMPLE_OWNERSHIP_SPECS],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    assert hashlib.sha256(semantic_bytes).hexdigest() == (
        "e73e7df6d43cb63b07f6c6b178b71832262e5bbf09a9f5fa50816ab7376332f2"
    )

    inventory = []
    for path in paths:
        content = (ROOT / path).read_bytes()
        inventory.append(
            f"{path}\t{len(content)}\t{hashlib.sha256(content).hexdigest()}"
        )
    assert _sha256(inventory) == (
            "c951e7e759e98d9f88b467f1760e21e2c39a26fc22f447735ac5e112c91ee649"
    )
