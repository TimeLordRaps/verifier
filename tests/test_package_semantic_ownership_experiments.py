from __future__ import annotations

from collections import Counter
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path

import pytest

from verifier.runtime.namespace_contracts import namespace_registry
from verifier.runtime.package_semantic_ownership import (
    SEMANTIC_OWNERSHIP_SPECS,
    validate_catalog,
)
from verifier.runtime.package_semantic_ownership_experiments import (
    EXPERIMENT_OWNERSHIP_SPECS,
)


ROOT = Path(__file__).parents[1]


EXPECTED_SEMANTICS = {
    "vstd-artifact-first-mechanism-study": ("POLICY", ("PROTOCOL",), 3),
    "vstd-experiment-catalog-records": ("DATA", ("POLICY",), 2),
    "vstd-github-verdict-neutrality-study-record": (
        "DATA",
        ("POLICY", "PROTOCOL"),
        1,
    ),
    "vstd-vgsat-architecture-documents": ("ARCH", ("POLICY", "PROTOCOL"), 3),
    "vstd-vgsat-artifact-audit": (
        "VERIFIER",
        ("ACTUATOR", "MEASUREMENT", "POLICY", "SENSOR", "TRANSACTION"),
        3,
    ),
    "vstd-vgsat-baseline-encoding-policy": ("POLICY", (), 1),
    "vstd-vgsat-benchmark-controller": (
        "BENCH",
        (
            "ACTUATOR",
            "CONTROLLER",
            "MEASUREMENT",
            "POLICY",
            "PROTOCOL",
            "SENSOR",
            "TRANSACTION",
        ),
        1,
    ),
    "vstd-vgsat-canonical-artifact-io": (
        "TRANSACTION",
        ("ACTUATOR", "MEASUREMENT", "SENSOR"),
        1,
    ),
    "vstd-vgsat-environment-declarations": ("ENV", ("POLICY", "PROTOCOL"), 3),
    "vstd-vgsat-freeze-ledger": (
        "LEDGER",
        (
            "ACTUATOR",
            "MEASUREMENT",
            "POLICY",
            "PROTOCOL",
            "SENSOR",
            "TRANSACTION",
        ),
        3,
    ),
    "vstd-vgsat-independent-record-validator": (
        "VERIFIER",
        ("ACTUATOR", "MEASUREMENT", "POLICY", "SENSOR"),
        1,
    ),
    "vstd-vgsat-instance-corpus": (
        "DATA",
        ("ACTUATOR", "MEASUREMENT", "POLICY", "SENSOR", "TRANSACTION"),
        2,
    ),
    "vstd-vgsat-metric-contract": ("MEASUREMENT", ("POLICY", "PROTOCOL"), 2),
    "vstd-vgsat-model-endpoint-harness": (
        "HARNESS",
        (
            "ACTUATOR",
            "MEASUREMENT",
            "POLICY",
            "PROTOCOL",
            "SENSOR",
            "TRANSACTION",
        ),
        1,
    ),
    "vstd-vgsat-model-prompt-policy": ("POLICY", ("PROTOCOL",), 4),
    "vstd-vgsat-native-verifier-adapters": (
        "VERIFIER",
        ("ACTUATOR", "MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR"),
        6,
    ),
    "vstd-vgsat-noise-measurement": (
        "MEASUREMENT",
        ("ACTUATOR", "POLICY", "SENSOR"),
        2,
    ),
    "vstd-vgsat-package-marker": ("DATA", (), 1),
    "vstd-vgsat-provenance-record-binding": (
        "VERIFIER",
        ("ACTUATOR", "LEDGER", "MEASUREMENT", "POLICY", "SENSOR"),
        1,
    ),
    "vstd-vgsat-public-result-records": ("DATA", ("MEASUREMENT", "POLICY"), 4),
    "vstd-vgsat-regression-harness": (
        "HARNESS",
        ("ACTUATOR", "MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR"),
        10,
    ),
    "vstd-vgsat-reserve-verifiers": (
        "VERIFIER",
        ("ACTUATOR", "MEASUREMENT", "POLICY", "SENSOR"),
        1,
    ),
    "vstd-vgsat-result-classification-policy": ("POLICY", ("MEASUREMENT",), 1),
    "vstd-vgsat-result-validator": (
        "VERIFIER",
        ("ACTUATOR", "MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR"),
        1,
    ),
    "vstd-vgsat-route-compiler": ("HARNESS", ("POLICY",), 1),
    "vstd-vgsat-sat-backend": (
        "VERIFIER",
        ("ACTUATOR", "CONTROLLER", "MEASUREMENT", "POLICY", "SENSOR"),
        1,
    ),
    "vstd-vgsat-study-governance": ("POLICY", ("PROTOCOL",), 4),
    "vstd-vgsat-trial-harness": (
        "HARNESS",
        (
            "ACTUATOR",
            "CONTROLLER",
            "MEASUREMENT",
            "POLICY",
            "PROTOCOL",
            "SENSOR",
            "TRANSACTION",
        ),
        1,
    ),
    "vstd-vgsat-vendored-license-policy": ("POLICY", (), 1),
    "vstd-vgsat-verifier-contract-protocol": ("PROTOCOL", ("POLICY",), 1),
}


EXPECTED_ROOT_ROLES = {
    "vstd-github-verdict-neutrality-study-record": (("RECEIPT", "APPLIES"),),
    "vstd-vgsat-architecture-documents": (("BENCH", "DOES_NOT_APPLY"),),
    "vstd-vgsat-artifact-audit": (("BENCH", "DOES_NOT_APPLY"),),
    "vstd-vgsat-baseline-encoding-policy": (
        ("BENCH", "DOES_NOT_APPLY"),
        ("HARNESS", "DOES_NOT_APPLY"),
        ("VERIFIER", "DOES_NOT_APPLY"),
    ),
    "vstd-vgsat-benchmark-controller": (
        ("HARNESS", "APPLIES"),
        ("MODEL", "DOES_NOT_APPLY"),
        ("RECEIPT", "APPLIES"),
        ("TIME", "APPLIES"),
        ("VERIFIER", "APPLIES"),
    ),
    "vstd-vgsat-environment-declarations": (("BENCH", "DOES_NOT_APPLY"),),
    "vstd-vgsat-freeze-ledger": (
        ("BENCH", "DOES_NOT_APPLY"),
        ("RECEIPT", "APPLIES"),
        ("TIME", "APPLIES"),
        ("VERIFIER", "APPLIES"),
    ),
    "vstd-vgsat-independent-record-validator": (
        ("BENCH", "DOES_NOT_APPLY"),
        ("GRAPH", "APPLIES"),
    ),
    "vstd-vgsat-instance-corpus": (("BENCH", "DOES_NOT_APPLY"),),
    "vstd-vgsat-metric-contract": (
        ("BENCH", "DOES_NOT_APPLY"),
        ("TIME", "APPLIES"),
    ),
    "vstd-vgsat-model-endpoint-harness": (
        ("BENCH", "DOES_NOT_APPLY"),
        ("MODEL", "DOES_NOT_APPLY"),
        ("TIME", "APPLIES"),
        ("TOKEN", "APPLIES"),
    ),
    "vstd-vgsat-model-prompt-policy": (
        ("BENCH", "DOES_NOT_APPLY"),
        ("HARNESS", "DOES_NOT_APPLY"),
        ("MODEL", "DOES_NOT_APPLY"),
    ),
    "vstd-vgsat-native-verifier-adapters": (("BENCH", "DOES_NOT_APPLY"),),
    "vstd-vgsat-noise-measurement": (
        ("BENCH", "APPLIES"),
        ("HARNESS", "APPLIES"),
        ("TIME", "APPLIES"),
        ("VERIFIER", "DOES_NOT_APPLY"),
    ),
    "vstd-vgsat-provenance-record-binding": (
        ("BENCH", "DOES_NOT_APPLY"),
        ("EVENT", "APPLIES"),
        ("GRAPH", "APPLIES"),
        ("RECEIPT", "APPLIES"),
        ("TIME", "APPLIES"),
    ),
    "vstd-vgsat-public-result-records": (
        ("BENCH", "APPLIES"),
        ("RECEIPT", "APPLIES"),
        ("TIME", "APPLIES"),
    ),
    "vstd-vgsat-regression-harness": (
        ("BENCH", "APPLIES"),
        ("GRAPH", "APPLIES"),
        ("MODEL", "DOES_NOT_APPLY"),
        ("RECEIPT", "APPLIES"),
        ("TIME", "APPLIES"),
        ("VERIFIER", "APPLIES"),
    ),
    "vstd-vgsat-reserve-verifiers": (("BENCH", "DOES_NOT_APPLY"),),
    "vstd-vgsat-result-classification-policy": (
        ("BENCH", "APPLIES"),
        ("TIME", "APPLIES"),
        ("VERIFIER", "APPLIES"),
    ),
    "vstd-vgsat-result-validator": (
        ("BENCH", "APPLIES"),
        ("RECEIPT", "APPLIES"),
    ),
    "vstd-vgsat-route-compiler": (
        ("BENCH", "DOES_NOT_APPLY"),
        ("VERIFIER", "APPLIES"),
    ),
    "vstd-vgsat-sat-backend": (
        ("BENCH", "DOES_NOT_APPLY"),
        ("TIME", "APPLIES"),
    ),
    "vstd-vgsat-study-governance": (("BENCH", "DOES_NOT_APPLY"),),
    "vstd-vgsat-trial-harness": (
        ("BENCH", "APPLIES"),
        ("GRAPH", "APPLIES"),
        ("MODEL", "DOES_NOT_APPLY"),
        ("RECEIPT", "APPLIES"),
        ("TIME", "APPLIES"),
        ("VERIFIER", "APPLIES"),
    ),
    "vstd-vgsat-verifier-contract-protocol": (
        ("BENCH", "DOES_NOT_APPLY"),
        ("VERIFIER", "DOES_NOT_APPLY"),
    ),
}


def _sha256(lines: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()


def _experiment_files() -> set[str]:
    return {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "experiments").rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    }


def _other_specs():
    selected_ids = {item.object_id for item in EXPERIMENT_OWNERSHIP_SPECS}
    return tuple(
        item for item in SEMANTIC_OWNERSHIP_SPECS if item.object_id not in selected_ids
    )


def _root_role_status(item, kind: str) -> str | None:
    return next(
        (decision.status for decision in item.root_role_decisions if decision.kind == kind),
        None,
    )


def test_partition_is_the_exact_current_experiment_residual() -> None:
    validated = validate_catalog(ROOT, EXPERIMENT_OWNERSHIP_SPECS)
    paths = [path for item in validated for path in item.owned_paths]
    other_paths = {path for item in _other_specs() for path in item.owned_paths}

    assert len(validated) == 30
    assert len(paths) == 67
    assert len(paths) == len(set(paths))
    assert set(paths) == _experiment_files() - other_paths
    assert set(paths).isdisjoint(other_paths)
    assert all(path.startswith("experiments/") for path in paths)
    assert all((ROOT / path).is_file() for path in paths)
    assert Counter(
        "root" if len(Path(path).parts) == 2 else Path(path).parts[1]
        for path in paths
    ) == {
        "root": 2,
        "artifact_first_mechanisms": 3,
        "github_verdict_neutrality": 1,
        "verifier_guided_sat": 61,
    }


def test_partition_pins_semantics_reasons_and_composition_layouts() -> None:
    actual = {
        item.object_id: (
            item.primary_kind,
            item.specializations,
            len(item.owned_paths),
        )
        for item in EXPERIMENT_OWNERSHIP_SPECS
    }
    assert actual == EXPECTED_SEMANTICS

    registry = namespace_registry()
    forbidden = {"AGENT", "ASSET", "BOT", "FINBOT", "MARKET", "OBJECT", "ROBOT", "SIM"}
    for item in EXPERIMENT_OWNERSHIP_SPECS:
        assert forbidden.isdisjoint((item.primary_kind, *item.specializations))
        assert all(registry[kind].extends is not None for kind in item.specializations)
        assert item.representation_role.strip()
        assert item.necessity_reason.strip()
        assert item.consequence_boundary.strip()

    operands = {
        item.object_id: item.operands
        for item in EXPERIMENT_OWNERSHIP_SPECS
        if item.operands
    }
    assert operands == {
        "vstd-vgsat-benchmark-controller": (
            ("data", ("vstd-vgsat-instance-corpus",)),
            ("verifier", ("vstd-vgsat-native-verifier-adapters",)),
        )
    }
    validate_catalog(ROOT, EXPERIMENT_OWNERSHIP_SPECS)


def test_retained_root_role_matrix_is_explicit_and_reasoned() -> None:
    actual = {
        item.object_id: tuple(
            (decision.kind, decision.status) for decision in item.root_role_decisions
        )
        for item in EXPERIMENT_OWNERSHIP_SPECS
        if item.root_role_decisions
    }
    assert actual == EXPECTED_ROOT_ROLES
    assert sum(len(rows) for rows in actual.values()) == 66
    assert Counter(status for rows in actual.values() for _, status in rows) == {
        "APPLIES": 39,
        "DOES_NOT_APPLY": 27,
    }

    registry = namespace_registry()
    for item in EXPERIMENT_OWNERSHIP_SPECS:
        for decision in item.root_role_decisions:
            assert registry[decision.kind].extends is None
            assert decision.kind != item.primary_kind
            assert decision.reason.strip()


def test_model_graph_time_and_real_world_consequences_are_not_collapsed() -> None:
    by_id = {item.object_id: item for item in EXPERIMENT_OWNERSHIP_SPECS}
    assert {
        item.object_id
        for item in EXPERIMENT_OWNERSHIP_SPECS
        if _root_role_status(item, "MODEL") == "APPLIES"
    } == set()
    assert {
        item.object_id
        for item in EXPERIMENT_OWNERSHIP_SPECS
        if _root_role_status(item, "MODEL") == "DOES_NOT_APPLY"
    } == {
        "vstd-vgsat-benchmark-controller",
        "vstd-vgsat-model-endpoint-harness",
        "vstd-vgsat-model-prompt-policy",
        "vstd-vgsat-regression-harness",
        "vstd-vgsat-trial-harness",
    }
    assert {
        item.object_id
        for item in EXPERIMENT_OWNERSHIP_SPECS
        if _root_role_status(item, "GRAPH") == "APPLIES"
    } == {
        "vstd-vgsat-independent-record-validator",
        "vstd-vgsat-provenance-record-binding",
        "vstd-vgsat-regression-harness",
        "vstd-vgsat-trial-harness",
    }
    assert {
        item.object_id
        for item in EXPERIMENT_OWNERSHIP_SPECS
        if _root_role_status(item, "TOKEN") == "APPLIES"
    } == {"vstd-vgsat-model-endpoint-harness"}

    endpoint = by_id["vstd-vgsat-model-endpoint-harness"].consequence_boundary
    for phrase in ("AGENT or BOT", "physical hardware", "financial decisions"):
        assert phrase in endpoint
    controller = by_id["vstd-vgsat-benchmark-controller"].consequence_boundary
    for phrase in ("unsandboxed", "MODEL confinement", "physical hardware", "transact money"):
        assert phrase in controller
    harness = by_id["vstd-vgsat-trial-harness"].consequence_boundary
    for phrase in ("not a security sandbox", "AGENT or BOT", "real-world actuator", "financial authority"):
        assert phrase in harness
    fixture_boundary = by_id["vstd-vgsat-regression-harness"].consequence_boundary
    assert "fixture LM" in fixture_boundary
    assert "not a real MODEL completion" in fixture_boundary


def test_partition_rejects_cross_owner_aliasing() -> None:
    other_specs = _other_specs()
    existing_path = next(path for item in other_specs for path in item.owned_paths)
    conflicting = replace(
        EXPERIMENT_OWNERSHIP_SPECS[0],
        object_id="vstd-experiment-overlap-adversary",
        owned_paths=(existing_path,),
    )
    with pytest.raises(ValueError, match="PATH_DUPLICATED"):
        validate_catalog(ROOT, other_specs + (conflicting,))


def test_partition_pins_mapping_declarations_and_current_source_bytes() -> None:
    ids = [item.object_id for item in EXPERIMENT_OWNERSHIP_SPECS]
    paths = [
        path for item in EXPERIMENT_OWNERSHIP_SPECS for path in item.owned_paths
    ]
    mapping = [
        f"{item.object_id}\t{item.primary_kind}\t{','.join(item.specializations)}\t{path}"
        for item in EXPERIMENT_OWNERSHIP_SPECS
        for path in item.owned_paths
    ]
    declarations = [
        json.dumps(
            asdict(item),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        for item in EXPERIMENT_OWNERSHIP_SPECS
    ]
    inventory = []
    for path in paths:
        content = (ROOT / path).read_bytes()
        inventory.append(
            f"{path}\t{len(content)}\t{hashlib.sha256(content).hexdigest()}"
        )

    assert _sha256(ids) == (
        "cfbacd4d7c5062fdf57fc76d9be26383cbf7567389a9cd36201ec372df793085"
    )
    assert _sha256(paths) == (
        "4012e9354f2b857fdd86ce62c7618d46027ec14604329c528edd277d67d7404a"
    )
    assert _sha256(mapping) == (
        "47b3a7814a5f57044c0b765aa41589c4785daadc8adce6676a4c06f7a6d598c2"
    )
    assert _sha256(declarations) == (
        "c1cbfe47f2f53f70ce68fa7740b7f75d964d265616ff48ef339212f5518ce201"
    )
    assert _sha256(inventory) == (
        "72bdbc8cd27a9316e6e3fba9b47b5a8518e0e1c6eb2f26f6e4ae00643d7c9db0"
    )
