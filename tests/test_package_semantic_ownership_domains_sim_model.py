"""Exact census, source grounding, and refutations for the SIM and MODEL ownership partition.

Terminology: Secure Hash Algorithm 256-bit (SHA-256).

The golden table below is a hand-written expectation.  It is a regression
contract, not independent evidence that the roles are correct: each role and
decision is additionally anchored to a marker string that must occur in the
owned source file, and the trap cases check that name-based promotions stay out.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import re
import shutil
from pathlib import Path

import pytest

from verifier.runtime import package_namespace_review as namespace_review
from verifier.runtime import package_semantic_ownership as central
from verifier.runtime.namespace_contracts import namespace_registry
from verifier.runtime.package_semantic_ownership_domains import DOMAIN_OWNERSHIP_SPECS
from verifier.runtime.package_semantic_ownership_domains_sim_model import (
    INTEGRATION_BLOCKERS,
    SIM_MODEL_OWNERSHIP_SPECS,
    SOURCE_DIGESTS,
    AggregationBlocker,
    aggregation_blockers,
    aggregation_ready,
    source_drift_failures,
)
from verifier.runtime.package_semantic_ownership_model import (
    RootRoleDecision,
    SemanticOwnershipSpec,
)


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "src/verifier/runtime/package_semantic_ownership_domains_sim_model.py"
CONTRACTS = "src/verifier/domains/contracts"
SIM_FILE = "src/verifier/domains/sim.py"
MODEL_FILE = "src/verifier/domains/model.py"

# Full-file SHA-256 of each owned path at the time these rows were audited.
# Drift is a failure: the source must be re-audited before the rows change.
EXPECTED_SHA256 = {
    "src/verifier/domains/contracts/model_artifact_bytes.py": "aae4dfc64fc34055320127ecbffbfe6a995e20dfac1db2adb5758853d1e5a4c3",
    "src/verifier/domains/contracts/model_checks.py": "832c411794f580e69626c88a71c0c1b4a451ea87c0429a3ffcad6ca1616c8e03",
    "src/verifier/domains/contracts/model_data_citation.py": "062b90e5764905e745e996012574631b413cefc96622e33ab1edf2f6f5c18bb2",
    "src/verifier/domains/contracts/model_data_lineage.py": "eb59369693ce9bcd6f338eacb880580f93b922276619a65179c73b695a7adf4a",
    "src/verifier/domains/contracts/model_hardware_observation.py": "10b569f2098caf2d89abe2b882b6243275b89ec587630f2f73e583e293e0f97b",
    "src/verifier/domains/contracts/model_quantization.py": "da17938ca763368bb31046c3d97272fb1ccc3f592804b7f3265f5bbf5080925a",
    "src/verifier/domains/contracts/model_train_citation.py": "14c25e1ded33ac0a481f02a91478f4402196296f02ac408f1adfad2962c60796",
    "src/verifier/domains/contracts/sim_checker.py": "8500764157b9af0ebf2643a09a41f0a2755fcb91a30fb525ad6724fefc7da2aa",
    "src/verifier/domains/contracts/sim_dynamics.py": "72c786f691d39658c464c59da94b6f6e1e2d601543340d4bdb0e53c99c9c256e",
    "src/verifier/domains/contracts/sim_external_law.py": "1ae09656fdf1405d025145bc79ac7cca30a9f5af67249820b0fbfa7399b90ca5",
    "src/verifier/domains/contracts/sim_fresh_bootstrap.py": "c1a5c46fffb060b5678009a756280923b370375b828b61d2401ecf75d77d0598",
    "src/verifier/domains/contracts/sim_fresh_worker.py": "937a96ee1afe6c86616364d561426e0cb3a832f96ea789c489ffae1c5124a015",
    "src/verifier/domains/contracts/sim_internal_core.py": "ffd2da61c0b889099e2167199653f8336ffd54558a91c3e7212107f5637dbc42",
    "src/verifier/domains/contracts/sim_internal_state.py": "967163ac95db3df7c2421682e95a4d8938b5e46ce7e870e1a9fdbde707633791",
    "src/verifier/domains/contracts/sim_isolation.py": "a179957ed9678c885f23a93138fada26ba8568ff11480b3d3dae71aedcd99f4d",
    "src/verifier/domains/contracts/sim_perspective.py": "adcd447253f6cd6c53a01043539347635ab45a1be33e1443cd76bf67ce4827ad",
    "src/verifier/domains/contracts/sim_resource.py": "838da6f7729ff4559bd13163ab2bb2586059750ecc113b9037d6746cca3dfde1",
    "src/verifier/domains/contracts/sim_resource_fresh.py": "d254cd1ea4ad229dd5eafcffe246d4d9afe89f4436eb7dcf979fd3b701c9a4f3",
    "src/verifier/domains/contracts/sim_resource_worker.py": "357b6aaf79b445a3a8686eb73fa02944b09e3166c71394a5ab6b15720fabc021",
    "src/verifier/domains/contracts/sim_response.py": "0d9afe7a445286a7a2fe116cdbaeb59ccf7a957c14e5ecb168e521e4c998a4cf",
    "src/verifier/domains/contracts/sim_shard_coverage.py": "5cb8239f19186181e95a7feaba4aa86a2f69c6459f8e6a24e9689928955c9395",
    "src/verifier/domains/contracts/sim_shard_relations.py": "47d095097d19584652f8d641596e4294b10774aaba722d19887aaecd34c63cfc",
    "src/verifier/domains/contracts/sim_shard_signatures.py": "81ece70f90346273c9cacbad1e36a8e30d6d732c770684c7ccd0d24bd3dfabc4",
    "src/verifier/domains/contracts/sim_surface_partition.py": "d17e50068b7b0960346b270d6c02c79694a851ad2c491bcf8a758d4bb444af9a",
    "src/verifier/domains/model.py": "82ed1aaa4825001af5e10aaf9cf4edafce5c6998ae044879b3fb0226043c5d99",
    "src/verifier/domains/sim.py": "f47eb43833c249869416e6b6e88456e3b4712bf53e9e17eff7d7ac6b29d8fc70",
}
# sha256 over the sorted lines "<path> <sha256>\n" for the 26 owned paths.
EXPECTED_CENSUS_SHA256 = "c84d834ce3e6466f068210b0cd1ea036c302f76e7a3ff5bb2d6f97086d3aa559"

# object_id: (owned path, primary kind, accumulated roles, root decisions).
GOLDEN = {
    "vstd-sim-specification-core": (
        SIM_FILE, "SIM", ("MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR"),
        {"VERIFIER": "APPLIES"}),
    "vstd-sim-native-checker-correspondence": (
        f"{CONTRACTS}/sim_checker.py", "SIM", ("POLICY",),
        {"VERIFIER": "APPLIES"}),
    "vstd-sim-dynamics-replay-verifier": (
        f"{CONTRACTS}/sim_dynamics.py", "SIM", ("POLICY",),
        {"VERIFIER": "APPLIES"}),
    "vstd-sim-external-law-statement": (
        f"{CONTRACTS}/sim_external_law.py", "SIM", ("POLICY",),
        {"VERIFIER": "APPLIES"}),
    "vstd-sim-fresh-source-loader": (
        f"{CONTRACTS}/sim_fresh_bootstrap.py", "SIM", ("ACTUATOR", "POLICY", "PROTOCOL"),
        {"HARNESS": "DOES_NOT_APPLY", "VERIFIER": "DOES_NOT_APPLY"}),
    "vstd-sim-fresh-process-meter": (
        f"{CONTRACTS}/sim_fresh_worker.py", "SIM",
        ("MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR", "TRANSACTION"),
        {"HARNESS": "DOES_NOT_APPLY", "VERIFIER": "DOES_NOT_APPLY"}),
    "vstd-sim-internal-hidden-change-enumerator": (
        f"{CONTRACTS}/sim_internal_core.py", "SIM", ("POLICY",),
        {"VERIFIER": "DOES_NOT_APPLY"}),
    "vstd-sim-internal-state-verifier": (
        f"{CONTRACTS}/sim_internal_state.py", "SIM", ("POLICY",),
        {"VERIFIER": "APPLIES"}),
    "vstd-sim-model-isolation-verifier": (
        f"{CONTRACTS}/sim_isolation.py", "SIM", ("POLICY",),
        {"HARDWARE": "DOES_NOT_APPLY", "VERIFIER": "APPLIES"}),
    "vstd-sim-macro-projection-verifier": (
        f"{CONTRACTS}/sim_perspective.py", "SIM", ("MEASUREMENT", "POLICY"),
        {"VERIFIER": "APPLIES"}),
    "vstd-sim-signed-resource-capture-verifier": (
        f"{CONTRACTS}/sim_resource.py", "SIM",
        ("ACTUATOR", "MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR"),
        {"HARNESS": "DOES_NOT_APPLY", "VERIFIER": "APPLIES"}),
    "vstd-sim-fresh-resource-execution-verifier": (
        f"{CONTRACTS}/sim_resource_fresh.py", "SIM",
        ("ACTUATOR", "MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR"),
        {"HARNESS": "DOES_NOT_APPLY", "VERIFIER": "APPLIES"}),
    "vstd-sim-resource-meter-process": (
        f"{CONTRACTS}/sim_resource_worker.py", "SIM",
        ("MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR"),
        {"HARNESS": "DOES_NOT_APPLY", "VERIFIER": "DOES_NOT_APPLY"}),
    "vstd-sim-action-response-verifier": (
        f"{CONTRACTS}/sim_response.py", "SIM", ("MEASUREMENT", "POLICY"),
        {"VERIFIER": "APPLIES"}),
    "vstd-sim-shard-coverage-verifier": (
        f"{CONTRACTS}/sim_shard_coverage.py", "SIM", ("POLICY",),
        {"VERIFIER": "APPLIES"}),
    "vstd-sim-shard-relations-verifier": (
        f"{CONTRACTS}/sim_shard_relations.py", "SIM", ("POLICY",),
        {"VERIFIER": "APPLIES"}),
    "vstd-sim-shard-signature-verifier": (
        f"{CONTRACTS}/sim_shard_signatures.py", "SIM", ("POLICY", "PROTOCOL", "SENSOR"),
        {"VERIFIER": "APPLIES"}),
    "vstd-sim-surface-partition-verifier": (
        f"{CONTRACTS}/sim_surface_partition.py", "SIM", ("POLICY",),
        {"VERIFIER": "APPLIES"}),
    "vstd-model-reproducibility-root-checker": (
        MODEL_FILE, "MODEL", ("MEASUREMENT", "POLICY"),
        {"ARCH": "APPLIES", "DATA": "DOES_NOT_APPLY", "VERIFIER": "APPLIES"}),
    "vstd-model-artifact-byte-commitment": (
        f"{CONTRACTS}/model_artifact_bytes.py", "MODEL", ("POLICY",),
        {"ARCH": "DOES_NOT_APPLY", "VERIFIER": "APPLIES"}),
    "vstd-model-native-check-certificate": (
        f"{CONTRACTS}/model_checks.py", "MODEL", ("MEASUREMENT", "POLICY"),
        {"ARCH": "APPLIES", "BENCH": "APPLIES", "DATA": "DOES_NOT_APPLY", "ENV": "DOES_NOT_APPLY",
         "HARDWARE": "DOES_NOT_APPLY", "TRAIN": "DOES_NOT_APPLY", "VERIFIER": "APPLIES"}),
    "vstd-model-data-citation-verifier": (
        f"{CONTRACTS}/model_data_citation.py", "MODEL", ("POLICY",),
        {"DATA": "DOES_NOT_APPLY", "VERIFIER": "APPLIES"}),
    "vstd-model-data-lineage-verifier": (
        f"{CONTRACTS}/model_data_lineage.py", "MODEL", ("POLICY",),
        {"DATA": "DOES_NOT_APPLY", "TRAIN": "DOES_NOT_APPLY", "VERIFIER": "APPLIES"}),
    "vstd-model-quantization-spec-verifier": (
        f"{CONTRACTS}/model_quantization.py", "MODEL", ("POLICY",),
        {"VERIFIER": "APPLIES"}),
    "vstd-model-train-citation-verifier": (
        f"{CONTRACTS}/model_train_citation.py", "MODEL", ("POLICY",),
        {"DATA": "DOES_NOT_APPLY", "TRAIN": "DOES_NOT_APPLY", "VERIFIER": "APPLIES"}),
    "vstd-model-observed-hardware-bracket": (
        f"{CONTRACTS}/model_hardware_observation.py", "MODEL",
        ("ACTUATOR", "MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR", "TRANSACTION"),
        {"HARDWARE": "APPLIES", "HARNESS": "DOES_NOT_APPLY", "VERIFIER": "APPLIES"}),
}

# Source anchors: a role or decision is grounded only if its marker text occurs
# in the owned file.  Markers are identifiers or literals, never prose.
ROLE_MARKERS = {
    "vstd-sim-specification-core": {
        "MEASUREMENT": "close(", "PROTOCOL": "Ed25519PublicKey",
        "SENSOR": "witness_keys", "POLICY": "Budget"},
    "vstd-sim-native-checker-correspondence": {"POLICY": "sim_checker_policy"},
    "vstd-sim-dynamics-replay-verifier": {"POLICY": "sim_dynamics_policy"},
    "vstd-sim-external-law-statement": {"POLICY": "sim_external_law_policy"},
    "vstd-sim-fresh-source-loader": {
        "ACTUATOR": "write_bytes", "POLICY": "source closure differs",
        "PROTOCOL": "sys.stdin.buffer.read"},
    "vstd-sim-fresh-process-meter": {
        "MEASUREMENT": "thread_time_ns", "POLICY": "meter bounds differ",
        "PROTOCOL": "step_binding", "SENSOR": "perf_counter_ns",
        "TRANSACTION": "_cleanup_tracing"},
    "vstd-sim-internal-hidden-change-enumerator": {"POLICY": "Budget"},
    "vstd-sim-internal-state-verifier": {"POLICY": "sim_internal_state_policy"},
    "vstd-sim-model-isolation-verifier": {"POLICY": "_MAX_ASSESSMENT_BYTES"},
    "vstd-sim-macro-projection-verifier": {
        "MEASUREMENT": "tolerance", "POLICY": "sim_perspective_policy"},
    "vstd-sim-signed-resource-capture-verifier": {
        "ACTUATOR": "subprocess.run", "MEASUREMENT": "thread_cpu",
        "POLICY": "_CEILINGS", "PROTOCOL": "_verify_signature",
        "SENSOR": "collector_key"},
    "vstd-sim-fresh-resource-execution-verifier": {
        "ACTUATOR": "subprocess.run", "MEASUREMENT": "thread_cpu_ns",
        "POLICY": "timeout_seconds", "PROTOCOL": "FRESH_STEP_BINDING_DIFFERS",
        "SENSOR": "sensor_digest"},
    "vstd-sim-resource-meter-process": {
        "MEASUREMENT": "thread_time_ns", "POLICY": "MAX_INPUT_BYTES",
        "PROTOCOL": "sys.stdin.buffer.read", "SENSOR": "tracemalloc"},
    "vstd-sim-action-response-verifier": {
        "MEASUREMENT": "max_response_delay", "POLICY": "_CEILINGS"},
    "vstd-sim-shard-coverage-verifier": {"POLICY": "retained_selection"},
    "vstd-sim-shard-relations-verifier": {"POLICY": "retained_selection"},
    "vstd-sim-shard-signature-verifier": {
        "PROTOCOL": "_PREFIX", "POLICY": "required_shards", "SENSOR": "public_keys"},
    "vstd-sim-surface-partition-verifier": {"POLICY": "sim_surface_partition_policy"},
    "vstd-model-reproducibility-root-checker": {
        "MEASUREMENT": "mean_squared_error", "POLICY": "tolerance"},
    "vstd-model-artifact-byte-commitment": {"POLICY": "model_artifact_bytes_policy"},
    "vstd-model-native-check-certificate": {
        "MEASUREMENT": "tolerance", "POLICY": "model_checks_policy"},
    "vstd-model-data-citation-verifier": {"POLICY": "model_data_policy"},
    "vstd-model-data-lineage-verifier": {
        "POLICY": "model_data_lineage_policy"},
    "vstd-model-quantization-spec-verifier": {"POLICY": "model_quantization_policy"},
    "vstd-model-train-citation-verifier": {"POLICY": "model_train_policy"},
    "vstd-model-observed-hardware-bracket": {
        "ACTUATOR": "_run_windows", "MEASUREMENT": "RESOURCE_EXHAUSTED",
        "POLICY": "model_hardware_policy", "PROTOCOL": "sys.stdin.buffer.read",
        "SENSOR": "platform.machine()", "TRANSACTION": "limits_verified_before_resume"},
}

DECISION_MARKERS = {
    ("vstd-sim-specification-core", "VERIFIER"): "def evaluate",
    ("vstd-sim-native-checker-correspondence", "VERIFIER"): "class _SimCheckerMechanism",
    ("vstd-sim-dynamics-replay-verifier", "VERIFIER"): "def _evaluate",
    ("vstd-sim-external-law-statement", "VERIFIER"): "def _evaluate",
    ("vstd-sim-fresh-source-loader", "HARNESS"): "sim_fresh_worker.measure",
    ("vstd-sim-fresh-source-loader", "VERIFIER"): "source closure differs",
    ("vstd-sim-fresh-process-meter", "HARNESS"): "def measure",
    ("vstd-sim-fresh-process-meter", "VERIFIER"): "def measure",
    ("vstd-sim-internal-hidden-change-enumerator", "VERIFIER"): "def enumerate_hidden_changes",
    ("vstd-sim-internal-state-verifier", "VERIFIER"): "def _evaluate",
    ("vstd-sim-model-isolation-verifier", "VERIFIER"): "def assess_sim_isolation",
    ("vstd-sim-model-isolation-verifier", "HARDWARE"): "_HARDWARE_KINDS",
    ("vstd-sim-macro-projection-verifier", "VERIFIER"): "def _evaluate",
    ("vstd-sim-signed-resource-capture-verifier", "VERIFIER"): "def _evaluate",
    ("vstd-sim-signed-resource-capture-verifier", "HARNESS"): "sim_resource_worker.py",
    ("vstd-sim-fresh-resource-execution-verifier", "VERIFIER"): "def recheck_sim_resource_fresh_certificate",
    ("vstd-sim-fresh-resource-execution-verifier", "HARNESS"): "subprocess.run",
    ("vstd-sim-resource-meter-process", "HARNESS"): "def main",
    ("vstd-sim-resource-meter-process", "VERIFIER"): "def measure",
    ("vstd-sim-action-response-verifier", "VERIFIER"): "def _evaluate",
    ("vstd-sim-shard-coverage-verifier", "VERIFIER"): "def _evaluate",
    ("vstd-sim-shard-relations-verifier", "VERIFIER"): "def _evaluate",
    ("vstd-sim-shard-signature-verifier", "VERIFIER"): "def _evaluate",
    ("vstd-sim-surface-partition-verifier", "VERIFIER"): "def _evaluate",
    ("vstd-model-reproducibility-root-checker", "VERIFIER"): "def evaluate",
    ("vstd-model-reproducibility-root-checker", "ARCH"): "network(architecture",
    ("vstd-model-reproducibility-root-checker", "DATA"): "samples",
    ("vstd-model-artifact-byte-commitment", "VERIFIER"): "def _evaluate",
    ("vstd-model-artifact-byte-commitment", "ARCH"): "artifact_bytes_sha256",
    ("vstd-model-native-check-certificate", "VERIFIER"): "def _evaluate",
    ("vstd-model-native-check-certificate", "ARCH"): '"arch": "ARCH"',
    ("vstd-model-native-check-certificate", "BENCH"): 'benchmark = selected["bench"]',
    ("vstd-model-native-check-certificate", "TRAIN"): "checkpoint_digests",
    ("vstd-model-native-check-certificate", "DATA"): '"data": "DATA"',
    ("vstd-model-native-check-certificate", "ENV"): '"environment": selected',
    ("vstd-model-native-check-certificate", "HARDWARE"): '"hardware": selected',
    ("vstd-model-data-citation-verifier", "VERIFIER"): "def _evaluate",
    ("vstd-model-data-citation-verifier", "DATA"): "DATA-1.2",
    ("vstd-model-data-lineage-verifier", "VERIFIER"): "def _evaluate",
    ("vstd-model-data-lineage-verifier", "TRAIN"): "train_data_bridge",
    ("vstd-model-data-lineage-verifier", "DATA"): "model_data_citation",
    ("vstd-model-quantization-spec-verifier", "VERIFIER"): "def _evaluate",
    ("vstd-model-train-citation-verifier", "VERIFIER"): "def _evaluate",
    ("vstd-model-train-citation-verifier", "TRAIN"): "TRAIN",
    ("vstd-model-train-citation-verifier", "DATA"): "model_data_citation",
    ("vstd-model-observed-hardware-bracket", "VERIFIER"): "def _evaluate",
    ("vstd-model-observed-hardware-bracket", "HARDWARE"): "process_backend",
    ("vstd-model-observed-hardware-bracket", "HARNESS"): "def _native_observation",
}

# Name-based promotions that the source does not support.  Each trap token must
# occur in the source (so the trap is real), and the role must stay absent.
REFUTED_PROMOTIONS = (
    ("vstd-sim-external-law-statement", "MEASUREMENT", "physical law"),
    ("vstd-sim-external-law-statement", "SENSOR", "physical law"),
    ("vstd-sim-model-isolation-verifier", "SENSOR", "sensor"),
    ("vstd-sim-internal-state-verifier", "SENSOR", "observation"),
    ("vstd-sim-internal-hidden-change-enumerator", "SENSOR", "observation"),
    ("vstd-sim-internal-hidden-change-enumerator", "MEASUREMENT", "observation"),
    ("vstd-sim-dynamics-replay-verifier", "MEASUREMENT", "replay"),
    ("vstd-sim-action-response-verifier", "CONTROLLER", "action"),
    ("vstd-sim-action-response-verifier", "ACTUATOR", "action"),
    ("vstd-sim-surface-partition-verifier", "PROTOCOL", "signature"),
    ("vstd-sim-surface-partition-verifier", "SENSOR", "observ"),
    ("vstd-sim-shard-coverage-verifier", "SENSOR", "shard"),
    ("vstd-sim-shard-relations-verifier", "PROTOCOL", "signature"),
    ("vstd-model-data-lineage-verifier", "LEDGER", "lineage"),
    ("vstd-model-artifact-byte-commitment", "ASSET", "ownership"),
    ("vstd-model-quantization-spec-verifier", "MEASUREMENT", "quantiz"),
)
REFUTED_DECISIONS = (
    ("vstd-model-artifact-byte-commitment", "ARCH", "APPLIES", "architecture"),
    ("vstd-model-data-lineage-verifier", "TRAIN", "APPLIES", "train"),
    ("vstd-sim-fresh-source-loader", "HARNESS", "APPLIES", "fresh"),
    ("vstd-sim-fresh-process-meter", "HARNESS", "APPLIES", "fresh"),
    ("vstd-sim-resource-meter-process", "HARNESS", "APPLIES", "worker"),
    ("vstd-sim-model-isolation-verifier", "HARDWARE", "APPLIES", "HARDWARE"),
    ("vstd-model-native-check-certificate", "HARDWARE", "APPLIES", "hardware"),
    ("vstd-model-observed-hardware-bracket", "HARNESS", "APPLIES", "native child"),
)
ACCUMULATING_ROLES = {
    "ACTUATOR", "ASSET", "CONTROLLER", "FINBOT", "LEDGER", "MARKET",
    "MEASUREMENT", "POLICY", "PROTOCOL", "ROBOT", "SENSOR", "TRANSACTION",
}


def _sha256(path: str) -> str:
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def _source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _identifiers(path: str) -> set[str]:
    tree = ast.parse(_source(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
    return names


def _row_diffs(spec: SemanticOwnershipSpec) -> list[str]:
    path, primary, roles, decisions = GOLDEN[spec.object_id]
    diffs: list[str] = []
    if spec.owned_paths != (path,):
        diffs.append(f"{spec.object_id}: owned_paths {spec.owned_paths} != {(path,)}")
    if spec.primary_kind != primary:
        diffs.append(f"{spec.object_id}: primary {spec.primary_kind} != {primary}")
    if spec.specializations != tuple(sorted(roles)):
        diffs.append(f"{spec.object_id}: roles {spec.specializations} != {tuple(sorted(roles))}")
    got = {item.kind: item.status for item in spec.root_role_decisions}
    if got != decisions:
        diffs.append(f"{spec.object_id}: decisions {got} != {decisions}")
    if spec.operands:
        diffs.append(f"{spec.object_id}: operands must remain unbound, got {spec.operands}")
    return diffs


def _inventory_diff(specs: tuple[SemanticOwnershipSpec, ...] | list[SemanticOwnershipSpec]) -> list[str]:
    """Compare a candidate partition with the golden census; empty means exact."""
    diffs: list[str] = []
    ids = [spec.object_id for spec in specs]
    for object_id in sorted({i for i in ids if ids.count(i) > 1}):
        diffs.append(f"duplicate object {object_id}")
    paths = [path for spec in specs for path in spec.owned_paths]
    for path in sorted({p for p in paths if paths.count(p) > 1}):
        diffs.append(f"duplicate path {path}")
    for object_id in sorted(set(GOLDEN) - set(ids)):
        diffs.append(f"missing object {object_id}")
    for object_id in sorted(set(ids) - set(GOLDEN)):
        diffs.append(f"extra object {object_id}")
    for spec in specs:
        if spec.object_id in GOLDEN:
            diffs.extend(_row_diffs(spec))
    expected_paths = sorted(path for path, _, _, _ in GOLDEN.values())
    if sorted(paths) != expected_paths:
        diffs.append("census path set differs")
    return diffs


def _disk_census() -> list[str]:
    contracts = ROOT / CONTRACTS
    found = [SIM_FILE, MODEL_FILE]
    found += [f"{CONTRACTS}/{p.name}" for p in contracts.glob("sim_*.py")]
    found += [f"{CONTRACTS}/{p.name}" for p in contracts.glob("model_*.py")]
    return sorted(found)


# ---- module shape and imports ----------------------------------------------

def test_module_is_zero_dependency_and_does_not_import_central_aggregate():
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    allowed = {
        "__future__", "dataclasses", "hashlib", "pathlib", "typing",
        "verifier.runtime.package_semantic_ownership_model",
    }
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert imported <= allowed, sorted(imported - allowed)
    assert not any("package_semantic_ownership_domains" in name for name in imported)


def test_export_is_tuple_of_specs_ready_for_aggregation():
    assert type(SIM_MODEL_OWNERSHIP_SPECS) is tuple
    assert all(type(spec) is SemanticOwnershipSpec for spec in SIM_MODEL_OWNERSHIP_SPECS)
    assert len(SIM_MODEL_OWNERSHIP_SPECS) == 26


# ---- exact census ------------------------------------------------------------

def test_census_paths_match_disk_exactly():
    owned = sorted(path for spec in SIM_MODEL_OWNERSHIP_SPECS for path in spec.owned_paths)
    on_disk = _disk_census()
    assert owned == on_disk
    assert len(owned) == 26
    assert sum(path.endswith("sim.py") or "/sim_" in path for path in owned) == 18
    assert sum(path.endswith("model.py") or "/model_" in path for path in owned) == 8


def test_census_matches_namespace_review_sim_paths():
    review_sim = set(namespace_review._SIM_PATHS)
    owned_sim = {p for spec in SIM_MODEL_OWNERSHIP_SPECS if spec.primary_kind == "SIM" for p in spec.owned_paths}
    assert owned_sim == review_sim


def test_census_digest_is_exact():
    lines = "".join(f"{path} {EXPECTED_SHA256[path]}\n" for path in sorted(EXPECTED_SHA256))
    assert hashlib.sha256(lines.encode("utf-8")).hexdigest() == EXPECTED_CENSUS_SHA256
    assert sorted(EXPECTED_SHA256) == sorted(GOLDEN[k][0] for k in GOLDEN)


@pytest.mark.parametrize("path", sorted(EXPECTED_SHA256))
def test_source_file_digest_is_exact(path):
    assert _sha256(path) == EXPECTED_SHA256[path]


def test_inventory_has_no_missing_extra_or_duplicate_objects():
    assert _inventory_diff(SIM_MODEL_OWNERSHIP_SPECS) == []
    ids = [spec.object_id for spec in SIM_MODEL_OWNERSHIP_SPECS]
    assert len(ids) == len(set(ids)) == 26


@pytest.mark.parametrize("object_id", sorted(GOLDEN))
def test_each_row_matches_golden_owner_kind_roles_decisions_and_unbound_layout(object_id):
    spec = next(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.object_id == object_id)
    assert _row_diffs(spec) == []


# ---- adversarial inventory fixtures ------------------------------------------

def _replace_spec(specs, object_id, **changes):
    return tuple(
        dataclasses.replace(spec, **changes) if spec.object_id == object_id else spec
        for spec in specs
    )


def test_good_fixture_is_clean():
    assert _inventory_diff(SIM_MODEL_OWNERSHIP_SPECS) == []


def test_wrong_owner_fixture_is_detected():
    specs = list(SIM_MODEL_OWNERSHIP_SPECS)
    a = next(s for s in specs if s.object_id == "vstd-sim-shard-coverage-verifier")
    b = next(s for s in specs if s.object_id == "vstd-sim-shard-relations-verifier")
    swapped = [
        dataclasses.replace(s, owned_paths=b.owned_paths) if s.object_id == a.object_id
        else dataclasses.replace(s, owned_paths=a.owned_paths) if s.object_id == b.object_id
        else s
        for s in specs
    ]
    assert any("owned_paths" in diff for diff in _inventory_diff(swapped))


def test_missing_row_fixture_is_detected():
    specs = tuple(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.object_id != "vstd-model-quantization-spec-verifier")
    assert "missing object vstd-model-quantization-spec-verifier" in _inventory_diff(specs)


def test_extra_and_duplicate_path_fixture_is_detected():
    duplicate = dataclasses.replace(
        next(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.object_id == "vstd-sim-shard-signature-verifier"),
        object_id="vstd-sim-shadow-signature-verifier",
    )
    diffs = _inventory_diff(SIM_MODEL_OWNERSHIP_SPECS + (duplicate,))
    assert "extra object vstd-sim-shadow-signature-verifier" in diffs
    assert any(diff.startswith("duplicate path") for diff in diffs)


def test_role_promotion_fixture_is_detected():
    specs = _replace_spec(
        SIM_MODEL_OWNERSHIP_SPECS, "vstd-sim-internal-hidden-change-enumerator",
        specializations=("POLICY", "SENSOR"),
    )
    assert any("roles" in diff for diff in _inventory_diff(specs))


def test_decision_flip_fixture_is_detected():
    original = next(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.object_id == "vstd-sim-fresh-process-meter")
    flipped = tuple(
        dataclasses.replace(item, status="APPLIES") if item.kind == "HARNESS" else item
        for item in original.root_role_decisions
    )
    specs = _replace_spec(SIM_MODEL_OWNERSHIP_SPECS, original.object_id, root_role_decisions=flipped)
    assert any("decisions" in diff for diff in _inventory_diff(specs))


def test_primary_kind_fixture_is_detected():
    specs = _replace_spec(SIM_MODEL_OWNERSHIP_SPECS, "vstd-model-quantization-spec-verifier", primary_kind="OBJECT")
    assert any("primary OBJECT" in diff for diff in _inventory_diff(specs))


def test_object_fallback_decision_fixture_is_detected():
    original = next(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.object_id == "vstd-sim-dynamics-replay-verifier")
    injected = original.root_role_decisions + (
        RootRoleDecision("OBJECT", "DOES_NOT_APPLY", "generic fallback"),
    )
    specs = _replace_spec(SIM_MODEL_OWNERSHIP_SPECS, original.object_id, root_role_decisions=injected)
    assert any("decisions" in diff for diff in _inventory_diff(specs))


# ---- source grounding -------------------------------------------------------

@pytest.mark.parametrize("object_id", sorted(ROLE_MARKERS))
def test_every_accumulated_role_has_a_source_marker_in_the_owned_file(object_id):
    spec = next(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.object_id == object_id)
    source = _source(spec.owned_paths[0])
    markers = ROLE_MARKERS[object_id]
    assert set(markers) == set(spec.specializations)
    for role, marker in markers.items():
        assert marker in source, f"{object_id}: {role} marker {marker!r} absent"


@pytest.mark.parametrize("key", sorted(DECISION_MARKERS))
def test_every_root_decision_has_a_source_marker_in_the_owned_file(key):
    object_id, kind = key
    spec = next(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.object_id == object_id)
    assert kind in {item.kind for item in spec.root_role_decisions}
    assert DECISION_MARKERS[key] in _source(spec.owned_paths[0])


@pytest.mark.parametrize("object_id", sorted(GOLDEN))
def test_necessity_and_decision_reasons_name_an_identifier_of_the_owned_source(object_id):
    spec = next(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.object_id == object_id)
    identifiers = _identifiers(spec.owned_paths[0])
    reasons = [spec.necessity_reason] + [item.reason for item in spec.root_role_decisions]
    for reason in reasons:
        tokens = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", reason))
        assert tokens & identifiers, f"{object_id}: no source identifier in {reason[:60]!r}"


@pytest.mark.parametrize("object_id,role,trap", REFUTED_PROMOTIONS)
def test_name_based_role_promotion_is_refuted(object_id, role, trap):
    spec = next(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.object_id == object_id)
    assert trap.lower() in _source(spec.owned_paths[0]).lower()
    assert role not in spec.specializations


@pytest.mark.parametrize("object_id,kind,status,trap", REFUTED_DECISIONS)
def test_refuted_root_decision_is_not_recorded(object_id, kind, status, trap):
    spec = next(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.object_id == object_id)
    decisions = {item.kind: item.status for item in spec.root_role_decisions}
    assert decisions.get(kind) != status
    assert trap.lower() in _source(spec.owned_paths[0]).lower() or trap in _source(spec.owned_paths[0])


def test_no_row_uses_object_fallback_or_unregistered_roles():
    registry = namespace_registry()
    for spec in SIM_MODEL_OWNERSHIP_SPECS:
        assert "OBJECT" not in spec.specializations
        assert all(item.kind != "OBJECT" for item in spec.root_role_decisions)
        for role in spec.specializations:
            assert role in ACCUMULATING_ROLES
            assert registry[role].extends == "OBJECT"
        for item in spec.root_role_decisions:
            assert registry[item.kind].extends is None
            assert item.reason.strip()


def test_asset_ledger_and_control_roles_are_never_assigned():
    roles = {role for spec in SIM_MODEL_OWNERSHIP_SPECS for role in spec.specializations}
    assert roles.isdisjoint({"ASSET", "LEDGER", "CONTROLLER", "FINBOT", "MARKET", "ROBOT"})


def test_bench_applies_to_native_check_certificate_from_executed_source_relation():
    spec = next(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.object_id == "vstd-model-native-check-certificate")
    decisions = {item.kind: item for item in spec.root_role_decisions}
    assert decisions["BENCH"].status == "APPLIES"
    assert "benchmark.payload" in decisions["BENCH"].reason


# ---- catalog validation and overlap -------------------------------------------

def test_unbound_batch_is_typed_unknown_and_not_centrally_aggregable():
    assert INTEGRATION_BLOCKERS == aggregation_blockers()
    assert len(INTEGRATION_BLOCKERS) == (18 * 4) + (8 * 7) == 128
    assert all(type(item) is AggregationBlocker for item in INTEGRATION_BLOCKERS)
    assert {item.code for item in INTEGRATION_BLOCKERS} == {"OPERAND_UNBOUND"}
    assert not aggregation_ready()
    with pytest.raises(
        ValueError,
        match="PACKAGE_SEMANTIC_OWNERSHIP_TYPED_LAYOUT_INVALID",
    ):
        central.validate_catalog(ROOT, SIM_MODEL_OWNERSHIP_SPECS)


def test_each_unbound_slot_reports_object_role_required_kind_and_reason():
    keys = {
        (item.object_id, item.operand_role, item.required_kind)
        for item in INTEGRATION_BLOCKERS
    }
    sim = next(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.primary_kind == "SIM")
    model = next(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.primary_kind == "MODEL")
    assert (sim.object_id, "objects", "OBJECT") in keys
    assert (model.object_id, "bench", "BENCH") in keys
    assert all(item.target_id is None and item.reason.strip() for item in INTEGRATION_BLOCKERS)


def test_invented_operand_targets_are_forbidden():
    """A shaped fake identifier must never stand in for an audited owner."""
    original = next(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.primary_kind == "SIM")
    mutated = _replace_spec(
        SIM_MODEL_OWNERSHIP_SPECS,
        original.object_id,
        operands=(("data", ("vstd-sim-unresolved-data-operand",)),),
    )
    blockers = aggregation_blockers(mutated)
    assert any(
        item.code == "OPERAND_TARGET_INVENTED"
        and item.object_id == original.object_id
        and item.operand_role == "data"
        for item in blockers
    )


def _external_owner(object_id: str, kind: str, *, operands=()) -> SemanticOwnershipSpec:
    return SemanticOwnershipSpec(
        object_id=object_id,
        primary_kind=kind,
        specializations=(),
        owned_paths=(f"src/verifier/external/{object_id}.py",),
        representation_role="test-only independently audited owner",
        necessity_reason="test-only owner exists to exercise exact typed binding",
        consequence_boundary="test-only row establishes no package claim",
        operands=operands,
        root_role_decisions=(),
    )


def test_missing_real_target_refuses_instead_of_treating_shape_as_existence():
    original = next(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.primary_kind == "SIM")
    mutated = _replace_spec(
        SIM_MODEL_OWNERSHIP_SPECS,
        original.object_id,
        operands=(("data", ("vstd-real-but-absent-data-owner",)),),
    )
    assert any(
        item.code == "OPERAND_TARGET_MISSING"
        and item.target_id == "vstd-real-but-absent-data-owner"
        for item in aggregation_blockers(mutated)
    )


def test_wrong_role_target_refuses_even_when_exact_id_exists():
    original = next(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.primary_kind == "SIM")
    wrong = _external_owner("vstd-audited-environment", "ENV")
    mutated = _replace_spec(
        SIM_MODEL_OWNERSHIP_SPECS,
        original.object_id,
        operands=(("data", (wrong.object_id,)),),
    )
    assert any(
        item.code == "OPERAND_TARGET_KIND_DIFFERS"
        and item.required_kind == "DATA"
        and item.target_id == wrong.object_id
        for item in aggregation_blockers(mutated, (wrong,))
    )


def test_exact_real_owner_binding_clears_only_its_own_slot_blocker():
    original = next(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.primary_kind == "SIM")
    data = _external_owner("vstd-audited-data", "DATA")
    mutated = _replace_spec(
        SIM_MODEL_OWNERSHIP_SPECS,
        original.object_id,
        operands=(("data", (data.object_id,)),),
    )
    blockers = aggregation_blockers(mutated, (data,))
    assert not any(
        item.object_id == original.object_id
        and item.operand_role == "data"
        and item.code.startswith("OPERAND_")
        for item in blockers
    )
    assert any(
        item.object_id == original.object_id
        and item.operand_role == "env"
        and item.code == "OPERAND_UNBOUND"
        for item in blockers
    )


def test_cyclic_candidate_targets_are_refused_independently_of_kind_errors():
    first, second = [
        spec for spec in SIM_MODEL_OWNERSHIP_SPECS if spec.primary_kind == "SIM"
    ][:2]
    mutated = _replace_spec(
        SIM_MODEL_OWNERSHIP_SPECS,
        first.object_id,
        operands=(("data", (second.object_id,)),),
    )
    mutated = _replace_spec(
        mutated,
        second.object_id,
        operands=(("data", (first.object_id,)),),
    )
    cycle_ids = {
        item.object_id for item in aggregation_blockers(mutated)
        if item.code == "OPERAND_CYCLE"
    }
    assert cycle_ids == {first.object_id, second.object_id}


@pytest.mark.parametrize("promotion", ("BOT", "ROBOT", "FINBOT"))
def test_bot_robot_finbot_promotion_requires_source_evidence(promotion):
    original = next(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.primary_kind == "SIM")
    changes = (
        {"primary_kind": promotion}
        if promotion == "BOT"
        else {"specializations": tuple(sorted(original.specializations + (promotion,)))}
    )
    mutated = _replace_spec(SIM_MODEL_OWNERSHIP_SPECS, original.object_id, **changes)
    assert any(
        item.code == "CONSEQUENCE_PROMOTION_UNSUPPORTED"
        and item.object_id == original.object_id
        for item in aggregation_blockers(mutated)
    )


def test_source_specific_refutation_cannot_be_promoted_to_a_role():
    object_id = "vstd-sim-external-law-statement"
    original = next(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.object_id == object_id)
    mutated = _replace_spec(
        SIM_MODEL_OWNERSHIP_SPECS,
        object_id,
        specializations=tuple(sorted(original.specializations + ("MEASUREMENT",))),
    )
    assert any(
        item.code == "SOURCE_REFUTATION_VIOLATED"
        and item.object_id == object_id
        and item.required_kind == "MEASUREMENT"
        for item in aggregation_blockers(mutated)
    )


def test_source_digest_table_is_exact_and_current():
    assert SOURCE_DIGESTS == {
        path: "sha256:" + digest for path, digest in EXPECTED_SHA256.items()
    }
    assert source_drift_failures(ROOT) == ()


def test_source_drift_is_a_typed_blocker(tmp_path):
    for relative in sorted(SOURCE_DIGESTS):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    changed = tmp_path / "src/verifier/domains/contracts/model_checks.py"
    changed.write_bytes(changed.read_bytes() + b"\n")
    failures = source_drift_failures(tmp_path)
    assert len(failures) == 1
    assert failures[0].code == "SOURCE_DRIFT"
    assert failures[0].object_id == "vstd-model-native-check-certificate"
    assert failures[0].source_path == "src/verifier/domains/contracts/model_checks.py"
    assert "semantic re-audit is required" in failures[0].reason


def test_fresh_execution_is_sim_evidence_not_harness_bot_or_physical_promotion():
    object_id = "vstd-sim-fresh-resource-execution-verifier"
    spec = next(s for s in SIM_MODEL_OWNERSHIP_SPECS if s.object_id == object_id)
    source = _source(spec.owned_paths[0])
    decisions = {item.kind: item.status for item in spec.root_role_decisions}
    assert spec.primary_kind == "SIM"
    assert decisions["VERIFIER"] == "APPLIES"
    assert decisions["HARNESS"] == "DOES_NOT_APPLY"
    assert set(spec.specializations).isdisjoint({"BOT", "ROBOT", "FINBOT", "CONTROLLER"})
    assert all(marker in source for marker in ("subprocess.run", '"-I"', '"-S"', '"-B"'))
    assert "no historical execution" in spec.consequence_boundary
    assert "no historical execution" in spec.root_role_decisions[-1].reason.lower() or "earlier-run" in " ".join(
        item.reason.lower() for item in spec.root_role_decisions
    )


def test_no_overlap_with_domain_aggregate_or_central_rows():
    ours = {spec.object_id for spec in SIM_MODEL_OWNERSHIP_SPECS}
    ours_paths = {path for spec in SIM_MODEL_OWNERSHIP_SPECS for path in spec.owned_paths}
    for other in list(DOMAIN_OWNERSHIP_SPECS) + list(central.SEMANTIC_OWNERSHIP_SPECS):
        if other.object_id in ours:
            pytest.fail(f"object id collision: {other.object_id}")
        overlap = ours_paths & set(other.owned_paths)
        assert not overlap, f"{other.object_id} also owns {sorted(overlap)}"
