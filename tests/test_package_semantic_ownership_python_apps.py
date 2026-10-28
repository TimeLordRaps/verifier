from __future__ import annotations

import hashlib
from pathlib import Path

from verifier.runtime.package_semantic_ownership_python_apps import (
    PYTHON_APPS_OWNERSHIP_SPECS,
)


ROOT = Path(__file__).parents[1]

# Each value pins primary kind, accumulated roles, fixed operands, and paths.
# It is intentionally independent of the declaration rows so semantic or
# denominator drift is visible in one focused review.
EXPECTED = {
    "vstd-python-public-api": (
        "ARCH", ("POLICY",), (), ("src/verifier/__init__.py",),
    ),
    "vstd-module-cli-entrypoint": (
        "PROTOCOL", ("ACTUATOR", "MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/__main__.py",),
    ),
    "vstd-consent-package-api": (
        "ARCH", (), (), ("src/verifier/consent/__init__.py",),
    ),
    "vstd-consent-stage-verifier": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR"), (),
        ("src/verifier/consent/stages.py",),
    ),
    "vstd-corrigibility-package-api": (
        "ARCH", (), (), ("src/verifier/corrigibility/__init__.py",),
    ),
    "vstd-benchmark-suite-verifier": (
        "VERIFIER", ("MEASUREMENT", "POLICY"), (),
        ("src/verifier/corrigibility/benchmark.py",),
    ),
    "vstd-corrigibility-containment-contracts": (
        "HARNESS", ("POLICY", "PROTOCOL"), (),
        ("src/verifier/corrigibility/contracts.py",),
    ),
    "vstd-training-data-contamination-assessor": (
        "VERIFIER", ("MEASUREMENT", "POLICY"), (),
        ("src/verifier/corrigibility/data.py",),
    ),
    "vstd-corrigibility-environment-profile": (
        "ENV", ("MEASUREMENT", "POLICY"), (),
        ("src/verifier/corrigibility/environment.py",),
    ),
    "vstd-corrigibility-provenance-ledger": (
        "LEDGER", ("POLICY", "TRANSACTION"), (),
        ("src/verifier/corrigibility/graph.py",),
    ),
    "vstd-training-checkpoint-ledger": (
        "LEDGER", ("MEASUREMENT", "POLICY", "TRANSACTION"), (),
        ("src/verifier/corrigibility/hyperparameters.py",),
    ),
    "vstd-model-reproducibility-profile": (
        "DATA", ("MEASUREMENT", "POLICY"), (),
        ("src/verifier/corrigibility/model.py",),
    ),
    "vstd-agent-bot-ontology-architecture": (
        "ARCH", ("POLICY",), (),
        ("src/verifier/corrigibility/ontology.py",),
    ),
    "vstd-operator-stop-authentication": (
        "PROTOCOL", ("POLICY",), (),
        ("src/verifier/corrigibility/operator_stop.py",),
    ),
    "vstd-capability-reward-lock": (
        "HARNESS", ("MEASUREMENT", "POLICY"), (),
        ("src/verifier/corrigibility/reward_lock.py",),
    ),
    "vstd-corrigibility-risk-assessor": (
        "VERIFIER", ("MEASUREMENT", "POLICY"), (),
        ("src/verifier/corrigibility/risk_profile.py",),
    ),
    "vstd-sim-trace-assessor": (
        "VERIFIER",
        ("ACTUATOR", "CONTROLLER", "MEASUREMENT", "POLICY", "SENSOR", "TRANSACTION"),
        (),
        ("src/verifier/corrigibility/simulation.py",),
    ),
    "vstd-tesla-cage-contract": (
        "HARNESS", ("MEASUREMENT", "POLICY"), (),
        ("src/verifier/corrigibility/tesla_cage.py",),
    ),
    "vstd-training-control-profile": (
        "POLICY", (), (), ("src/verifier/corrigibility/train_profile.py",),
    ),
    "vstd-data-package-api": (
        "ARCH", (), (), ("src/verifier/data/__init__.py",),
    ),
    "vstd-graph-level-verifier": (
        "VERIFIER", ("ACTUATOR", "MEASUREMENT", "POLICY", "SENSOR", "TRANSACTION"), (),
        ("src/verifier/data/graph_level.py",),
    ),
    "vstd-provenance-hypergraph-ledger": (
        "LEDGER", ("ASSET", "MEASUREMENT", "POLICY", "TRANSACTION"), (),
        ("src/verifier/data/models.py",),
    ),
    "vstd-data-receipt-lifecycle": (
        "RECEIPT", ("ACTUATOR", "MEASUREMENT", "POLICY", "SENSOR", "TRANSACTION"),
        (("hardware", ("vstd-hardware",)), ("subject", ("vstd-data",))),
        ("src/verifier/data/receipt.py",),
    ),
    "vstd-environments-package-api": (
        "ARCH", (), (), ("src/verifier/environments/__init__.py",),
    ),
    "vstd-environment-record-contracts": (
        "ENV", ("POLICY",), (), ("src/verifier/environments/contracts.py",),
    ),
    "vstd-environment-assessor": (
        "VERIFIER", ("ACTUATOR", "MEASUREMENT", "POLICY", "SENSOR", "TRANSACTION"), (),
        ("src/verifier/environments/assessment.py",),
    ),
    "vstd-environment-integration-projection": (
        "ARCH", ("POLICY",), (), ("src/verifier/environments/integration.py",),
    ),
    "vstd-environment-specimen-checker": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/environments/specimen_checks.py",),
    ),
    "vstd-environment-synthetic-specimens": (
        "HARNESS",
        ("ACTUATOR", "CONTROLLER", "MEASUREMENT", "POLICY", "SENSOR", "TRANSACTION"),
        (),
        ("src/verifier/environments/specimens.py",),
    ),
    "vstd-experimental-workflow-package-api": (
        "ARCH", (), (), ("src/verifier/experimental_workflow/__init__.py",),
    ),
    "vstd-github-snapshot-event-adapter": (
        "VERIFIER", ("POLICY",), (),
        ("src/verifier/experimental_workflow/github.py",),
    ),
    "vstd-experimental-workflow-profile": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        (
            "src/verifier/experimental_workflow/profile.py",
            "src/verifier/experimental_workflow/schema.py",
        ),
    ),
    "vstd-identity-package-api": (
        "ARCH", (), (), ("src/verifier/identity/__init__.py",),
    ),
    "vstd-identity-token-records": (
        "TOKEN", ("LEDGER", "POLICY", "PROTOCOL"), (),
        ("src/verifier/identity/tokens.py",),
    ),
    "vstd-identity-policy-evaluator": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        (
            "src/verifier/identity/evaluator.py",
            "src/verifier/identity/invariants.py",
        ),
    ),
    "vstd-identity-adversarial-audit": (
        "HARNESS", ("MEASUREMENT", "POLICY"), (),
        ("src/verifier/identity/audit.py",),
    ),
    "vstd-layer4-package-api": (
        "ARCH", (), (), ("src/verifier/layer4/__init__.py",),
    ),
    "vstd-refutation-surface-policy": (
        "POLICY", (), (), ("src/verifier/layer4/surface.py",),
    ),
    "vstd-refutability-closure-verifier": (
        "VERIFIER", ("POLICY",), (), ("src/verifier/layer4/closure.py",),
    ),
    "vstd-schema-package-marker": (
        "DATA", (), (), ("src/verifier/schemas/__init__.py",),
    ),
}


# Root-role decisions are the only ownership-level applicability claims.  Each
# pinned APPLIES row is an accumulated role evidenced by quoted owned source.
# A DOES_NOT_APPLY is pinned only for the exact, exhaustive role boundary in the
# closed ontology owner; negative prose and type-distinction sentences do not.
EXPECTED_ROOT_ROLE_DECISIONS = {
    ("vstd-corrigibility-environment-profile", "HARDWARE"): "APPLIES",
    ("vstd-agent-bot-ontology-architecture", "SIM"): "APPLIES",
    **{
        ("vstd-agent-bot-ontology-architecture", kind): "DOES_NOT_APPLY"
        for kind in (
            "ACTOR", "BENCH", "COLLECTIVE", "DATA", "ENV", "GRAPH",
            "HARDWARE", "HARNESS", "HUMAN", "HYPER", "IDENTITY", "MODEL",
            "OWNER", "RECEIPT", "ROLE", "TOKEN", "TRAIN", "VERIFIER",
        )
    },
    ("vstd-tesla-cage-contract", "HARDWARE"): "APPLIES",
    ("vstd-graph-level-verifier", "GRAPH"): "APPLIES",
    ("vstd-environment-synthetic-specimens", "ENV"): "APPLIES",
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
        for item in PYTHON_APPS_OWNERSHIP_SPECS
    }
    assert actual == EXPECTED
    assert len(actual) == 40

    paths = [
        path
        for item in PYTHON_APPS_OWNERSHIP_SPECS
        for path in item.owned_paths
    ]
    assert len(paths) == 42
    assert len(paths) == len(set(paths))
    assert all((ROOT / path).is_file() for path in paths)
    assert all(item.representation_role.strip() for item in PYTHON_APPS_OWNERSHIP_SPECS)
    assert all(item.necessity_reason.strip() for item in PYTHON_APPS_OWNERSHIP_SPECS)
    assert all(item.consequence_boundary.strip() for item in PYTHON_APPS_OWNERSHIP_SPECS)


def test_partition_preserves_nonpromotion_and_consequence_boundaries() -> None:
    specs = {item.object_id: item for item in PYTHON_APPS_OWNERSHIP_SPECS}

    ontology = specs["vstd-agent-bot-ontology-architecture"]
    assert ontology.primary_kind == "ARCH"
    assert ontology.specializations == ("POLICY",)
    assert "execute no AGENT or BOT" in ontology.consequence_boundary
    assert "ROBOT, FINBOT" in ontology.consequence_boundary

    cage = specs["vstd-tesla-cage-contract"]
    assert cage.primary_kind == "HARNESS"
    assert cage.specializations == ("MEASUREMENT", "POLICY")
    assert "implements no preemption" in cage.consequence_boundary

    receipt = specs["vstd-data-receipt-lifecycle"]
    assert "non-atomic local multi-file write" in receipt.consequence_boundary
    assert "without external witness or durable truth" in receipt.consequence_boundary

    specimen = specs["vstd-environment-synthetic-specimens"]
    for term in ("synthetic", "unsandboxed", "BOT", "ROBOT", "FINBOT", "physical", "financial"):
        assert term in specimen.consequence_boundary

    model = specs["vstd-model-reproducibility-profile"]
    assert model.primary_kind == "DATA"
    assert "do not load, train, infer with, evaluate" in model.consequence_boundary


def test_partition_has_no_generic_object_or_unearned_consequence_role() -> None:
    for item in PYTHON_APPS_OWNERSHIP_SPECS:
        kinds = (item.primary_kind, *item.specializations)
        assert "OBJECT" not in kinds
        assert "MARKET" not in kinds
        assert "BOT" not in kinds
        assert "ROBOT" not in kinds
        assert "FINBOT" not in kinds
        assert "MODEL" not in kinds
        assert "AGENT" not in kinds
    assert [
        item.object_id
        for item in PYTHON_APPS_OWNERSHIP_SPECS
        if "ASSET" in (item.primary_kind, *item.specializations)
    ] == ["vstd-provenance-hypergraph-ledger"]


def test_partition_pins_audit_digests() -> None:
    assert _sha256([item.object_id for item in PYTHON_APPS_OWNERSHIP_SPECS]) == (
        "dde7874eb58f8a9ff179e0f8569a51b74f473ea34c32b0c99e08171e8e532ce8"
    )

    paths = [
        path
        for item in PYTHON_APPS_OWNERSHIP_SPECS
        for path in item.owned_paths
    ]
    assert _sha256(paths) == (
        "9548c4fc9205607722a818dbc53724927525747d585b843a59ccacb2b7154719"
    )

    mapping = [
        f"{item.object_id}\t{path}"
        for item in PYTHON_APPS_OWNERSHIP_SPECS
        for path in item.owned_paths
    ]
    assert _sha256(mapping) == (
        "47ac87f4610badb92c8207af0b0ec0dc687a1bf4ac39223ca9945c3672bd73a1"
    )

    inventory = []
    for path in paths:
        content = (ROOT / path).read_bytes()
        inventory.append(
            f"{path}\t{len(content)}\t{hashlib.sha256(content).hexdigest()}"
        )
    assert _sha256(inventory) == (
        "9a29dafb28a73053d693bdee5e6f3afd169696f7ba8327dacbf2a95bc1941b9c"
    )


def test_root_role_decisions_are_exact_and_only_closed_boundary_refutes() -> None:
    decisions = [
        ((item.object_id, decision.kind), decision.status)
        for item in PYTHON_APPS_OWNERSHIP_SPECS
        for decision in item.root_role_decisions
    ]
    assert len(decisions) == len(EXPECTED_ROOT_ROLE_DECISIONS)
    assert dict(decisions) == EXPECTED_ROOT_ROLE_DECISIONS
    assert sum(status == "DOES_NOT_APPLY" for _, status in decisions) == 18


def test_open_closure_rows_cannot_pin_a_negative_or_type_distinction_as_absent() -> None:
    specs = {item.object_id: item for item in PYTHON_APPS_OWNERSHIP_SPECS}

    consent = specs["vstd-consent-stage-verifier"]
    assert consent.root_role_decisions == ()
    assert "HUMAN" not in (consent.primary_kind, *consent.specializations)
    assert "prove voluntary human consent" in consent.consequence_boundary

    training = specs["vstd-training-control-profile"]
    assert training.root_role_decisions == ()
    assert "MODEL" not in (training.primary_kind, *training.specializations)
    assert training.primary_kind == "POLICY"
    assert training.specializations == ()


def test_legitimate_applies_rows_keep_their_accumulated_roles() -> None:
    specs = {item.object_id: item for item in PYTHON_APPS_OWNERSHIP_SPECS}

    assert specs["vstd-graph-level-verifier"].specializations == (
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        "TRANSACTION",
    )
    assert specs["vstd-environment-synthetic-specimens"].primary_kind == "HARNESS"
    assert "CONTROLLER" in specs["vstd-environment-synthetic-specimens"].specializations
    assert specs["vstd-tesla-cage-contract"].primary_kind == "HARNESS"
    assert specs["vstd-agent-bot-ontology-architecture"].primary_kind == "ARCH"
