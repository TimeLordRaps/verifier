# Terminology: abstract syntax tree (AST).
from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
import re
import shutil
from pathlib import Path

import pytest

from verifier.core.namespace import NamespaceObject, ObjectKind, validate_object_layout
from verifier.runtime import package_semantic_ownership_domains_context as ctx
from verifier.runtime.namespace_contracts import compatible_specialization, namespace_registry


ROOT = Path(__file__).parents[1]
SRC = ROOT / "src"
MODULE_PATH = ROOT / "src" / "verifier" / "runtime" / "package_semantic_ownership_domains_context.py"
ROOT_MANIFEST = ROOT / "objects.vstd"
CONTRACTS = "src/verifier/domains/contracts/"

# Structural oracle only: primary kind and owned paths, typed from the batch
# definition.  It proves coverage and ownership, never role status.  Role status
# is judged by the source-bound LEDGER below.
EXPECTED_ROWS = {
    "vstd-environment": ("ENV", (
        "src/verifier/domains/contracts/env_checks.py",
        "src/verifier/domains/contracts/env_checks_projection.py",
        "src/verifier/domains/contracts/env_configuration_surface.py",
        "src/verifier/domains/contracts/env_executable.py",
        "src/verifier/domains/contracts/env_pin_closure.py",
        "src/verifier/domains/env.py",
    )),
    "vstd-event": ("EVENT", (
        "src/verifier/domains/contracts/event_closure.py",
        "src/verifier/domains/contracts/event_dispatch.py",
        "src/verifier/domains/contracts/event_prerequisites.py",
    )),
    "vstd-package-graph": ("GRAPH", (
        "src/verifier/domains/contracts/graph_closure.py",
        "src/verifier/domains/contracts/graph_lineage.py",
        "src/verifier/domains/contracts/graph_order.py",
        "src/verifier/domains/contracts/graph_statics.py",
    )),
    "vstd-hypergraph": ("HYPER", (
        "src/verifier/domains/contracts/hyper_closure.py",
        "src/verifier/domains/contracts/hyper_composed_ceiling.py",
        "src/verifier/domains/contracts/hyper_unknown_absorption.py",
    )),
    "vstd-identity": ("IDENTITY", (
        "src/verifier/domains/identity.py",
        "src/verifier/domains/contracts/identity_lifecycle.py",
        "src/verifier/domains/contracts/identity_lifecycle_replay.py",
        "src/verifier/domains/contracts/identity_occupancy.py",
        "src/verifier/domains/contracts/identity_presentation.py",
        "src/verifier/domains/contracts/identity_scope.py",
    )),
    "vstd-space": ("SPACE", (
        "src/verifier/domains/contracts/space_closure.py",
        "src/verifier/domains/contracts/space_layout.py",
        "src/verifier/domains/contracts/space_migration.py",
    )),
    "vstd-time": ("TIME", (
        "src/verifier/domains/contracts/time_closure.py",
        "src/verifier/domains/contracts/time_order.py",
        "src/verifier/domains/contracts/time_strict.py",
    )),
    "vstd-role": ("ROLE", (
        "src/verifier/domains/role.py",
        "src/verifier/domains/contracts/role_closure.py",
        "src/verifier/domains/contracts/role_constraints.py",
        "src/verifier/domains/contracts/role_lifecycle.py",
    )),
    "vstd-owner": ("OWNER", (
        "src/verifier/domains/owner.py",
        "src/verifier/domains/contracts/owner_eligibility.py",
        "src/verifier/domains/contracts/owner_forks.py",
        "src/verifier/domains/contracts/owner_replay.py",
    )),
    "vstd-receipt": ("RECEIPT", (
        "src/verifier/domains/contracts/receipt_authenticity.py",
        "src/verifier/domains/contracts/receipt_chain.py",
        "src/verifier/domains/contracts/receipt_prerequisite_closure.py",
        "src/verifier/domains/contracts/receipt_statics.py",
        "src/verifier/domains/contracts/receipt_validation_replay.py",
    )),
}
EXPECTED_KIND_COUNTS = {"ENV": 6, "EVENT": 3, "GRAPH": 4, "HYPER": 3, "IDENTITY": 6,
                        "SPACE": 3, "TIME": 3, "ROLE": 4, "OWNER": 4, "RECEIPT": 5}

# Exception ledger: every cell that is NOT DOES_NOT_APPLY, written from reading the
# owned source.  Each entry names the cited symbol and a fact token that must occur
# in that symbol's text.  Any cell absent from this ledger must be DOES_NOT_APPLY,
# and that absence is checked mechanically by the module's executable gates.  The
# facts are checked against the live source, so editing the module to agree with
# a wrong table still fails when the source no longer carries the fact.
LEDGER = {
    ("vstd-environment", "POLICY"): ("APPLIES", (
        (CONTRACTS + "env_checks.py", "_policy", r"_policy\("),)),
    ("vstd-environment", "MEASUREMENT"): ("UNKNOWN", (
        ("src/verifier/domains/env.py", "evaluate", r"wall_seconds"),)),
    ("vstd-environment", "VERIFIER"): ("APPLIES", (
        (CONTRACTS + "env_checks.py", "recheck_env_checks_certificate", r"raise "),)),
    ("vstd-event", "POLICY"): ("APPLIES", (
        (CONTRACTS + "event_closure.py", "_evaluate", r"policy="),)),
    ("vstd-event", "PROTOCOL"): ("APPLIES", (
        (CONTRACTS + "event_dispatch.py", "_replay_log", r"not in topic_of|pair not in pending"),)),
    ("vstd-event", "TRANSACTION"): ("APPLIES", (
        (CONTRACTS + "event_dispatch.py", "_replay_log", r"acknowledged"),)),
    ("vstd-event", "VERIFIER"): ("APPLIES", (
        (CONTRACTS + "event_dispatch.py", "recheck_event_dispatch_certificate", r"raise "),)),
    ("vstd-package-graph", "POLICY"): ("APPLIES", (
        (CONTRACTS + "graph_statics.py", "_policy", r"_policy\("),)),
    ("vstd-package-graph", "VERIFIER"): ("APPLIES", (
        (CONTRACTS + "graph_closure.py", "recheck_graph_closure_certificate", r"raise "),)),
    ("vstd-hypergraph", "ACTUATOR"): ("APPLIES", (
        (CONTRACTS + "hyper_unknown_absorption.py", "bound_children", r"objective=\w+\["),)),
    ("vstd-hypergraph", "POLICY"): ("APPLIES", (
        (CONTRACTS + "hyper_closure.py", "_policy", r"_policy\("),)),
    ("vstd-hypergraph", "VERIFIER"): ("APPLIES", (
        (CONTRACTS + "hyper_closure.py", "recheck_hyper_closure_certificate", r"raise "),)),
    ("vstd-identity", "CONTROLLER"): ("UNKNOWN", (
        (CONTRACTS + "identity_presentation.py", "_evaluate", r"terminal_controller"),)),
    ("vstd-identity", "POLICY"): ("APPLIES", (
        (CONTRACTS + "identity_lifecycle.py", "_policy", r"_policy\("),)),
    ("vstd-identity", "PROTOCOL"): ("APPLIES", (
        (CONTRACTS + "identity_presentation.py", "_verify_signature", r"signature"),)),
    ("vstd-identity", "VERIFIER"): ("APPLIES", (
        (CONTRACTS + "identity_lifecycle.py", "recheck_identity_lifecycle_certificate", r"raise "),)),
    ("vstd-space", "POLICY"): ("APPLIES", (
        (CONTRACTS + "space_layout.py", "_policy", r"_policy\("),)),
    ("vstd-space", "VERIFIER"): ("APPLIES", (
        (CONTRACTS + "space_closure.py", "recheck_space_closure_certificate", r"raise "),)),
    ("vstd-time", "POLICY"): ("APPLIES", (
        (CONTRACTS + "time_closure.py", "_policy", r"_policy\("),)),
    ("vstd-time", "VERIFIER"): ("APPLIES", (
        (CONTRACTS + "time_order.py", "recheck_time_order_certificate", r"raise "),)),
    ("vstd-role", "POLICY"): ("APPLIES", (
        (CONTRACTS + "role_constraints.py", "_policy", r"retained_selection\.policy"),)),
    ("vstd-role", "PROTOCOL"): ("APPLIES", (
        (CONTRACTS + "role_closure.py", "_evaluate", r'\["taking"\]|\["leaving"\]'),)),
    ("vstd-role", "VERIFIER"): ("APPLIES", (
        (CONTRACTS + "role_closure.py", "recheck_role_closure_certificate", r"raise "),)),
    ("vstd-receipt", "MEASUREMENT"): ("UNKNOWN", (
        (CONTRACTS + "receipt_statics.py", "_execution", r"elapsed_ms"),)),
    ("vstd-owner", "ASSET"): ("APPLIES", (
        ("src/verifier/domains/owner.py", "evaluate", r"holding"),)),
    ("vstd-owner", "POLICY"): ("APPLIES", (
        (CONTRACTS + "owner_eligibility.py", "_policy", r"_policy\("),)),
    ("vstd-owner", "PROTOCOL"): ("APPLIES", (
        (CONTRACTS + "owner_replay.py", "_replay", r'event\["from"\]'),)),
    ("vstd-owner", "VERIFIER"): ("APPLIES", (
        ("src/verifier/domains/owner.py", "evaluate", r"raise "),)),
    ("vstd-receipt", "POLICY"): ("APPLIES", (
        (CONTRACTS + "receipt_authenticity.py", "_policy", r"_policy\("),)),
    ("vstd-receipt", "PROTOCOL"): ("APPLIES", (
        (CONTRACTS + "receipt_authenticity.py", "_evaluate", r"signature"),)),
    ("vstd-receipt", "VERIFIER"): ("APPLIES", (
        (CONTRACTS + "receipt_validation_replay.py", "recheck_receipt_validation_replay_certificate", r"raise "),)),
}

SENSOR_READ_ONLY = (
    "import hashlib\n"
    "from pathlib import Path\n\n\n"
    "def evaluate(path):\n"
    "    return hashlib.sha256(Path(path).read_bytes()).hexdigest()\n"
)
SENSOR_ACQUISITION = (
    "def evaluate(sensor, policy):\n"
    "    raw = sensor.read_sample()\n"
    "    calibrated = (raw - policy[\"calibration_offset\"]) * policy[\"gain\"]\n"
    "    if not policy[\"envelope_min\"] <= calibrated <= policy[\"envelope_max\"]:\n"
    "        raise Refuted(\"reading outside calibrated envelope\")\n"
    "    return {\"sample_rate\": policy[\"sample_rate\"], \"fault_mode\": None, \"value\": calibrated}\n"
)
MEASURAND_DECLARED = (
    "MEASURAND = {\"phenomenon\": \"air temperature\", \"units\": \"kelvin\", \"missingness\": \"NaN\"}\n"
)
ROUTE_LOOKUP = (
    "from verifier.domains.contracts.current_object_routes import _ROUTES\n\n\n"
    "def route(version, coordinate):\n"
    "    return _ROUTES[(version, coordinate)]\n"
)


def _decision(object_id: str, role: str) -> ctx.SourceRoleDecision:
    return next(d for d in ctx.DOMAIN_CONTEXT_ROLE_DECISIONS if d.object_id == object_id and d.role == role)


def _spec(object_id: str) -> ctx.SemanticOwnershipSpec:
    return next(s for s in ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS if s.object_id == object_id)


def _validate(specs=None, decisions=None, census=None, digests=None) -> None:
    ctx._validate(
        ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS if specs is None else specs,
        ctx.DOMAIN_CONTEXT_ROLE_DECISIONS if decisions is None else decisions,
        ctx.DOMAIN_CONTEXT_SOURCE_CENSUS if census is None else census,
        ctx.DOMAIN_CONTEXT_SOURCE_DIGESTS if digests is None else digests,
    )


def _copy_census(destination: Path) -> None:
    for row in ctx.DOMAIN_CONTEXT_SOURCE_CENSUS:
        target = destination / row.path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / row.path, target)


def _top_level(source: str, symbol: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    tree = ast.parse(source)
    return next(n for n in tree.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == symbol)


def _span_of(source: str, symbol: str) -> tuple[int, int]:
    node = _top_level(source, symbol)
    return node.lineno, node.end_lineno or node.lineno


def _docstring_span(source: str, symbol: str) -> tuple[int, int]:
    first = _top_level(source, symbol).body[0]
    assert isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
    return first.lineno, first.end_lineno or first.lineno


def _symbol_text(path: Path, symbol: str) -> str:
    source = path.read_text(encoding="utf-8")
    node = _top_level(source, symbol)
    return ast.get_source_segment(source, node) or ""


def _fixture_decision(object_id: str, role: str, status: str, path: str, symbol: str, file: Path):
    start, end = _span_of(file.read_text(encoding="utf-8"), symbol)
    return ctx.SourceRoleDecision(object_id, role, status,
                                  (ctx.SourceEvidence(path, symbol, start, end),), "fixture")


def _whole_module_decision(object_id: str, role: str, status: str, path: str, file: Path):
    lines = len(file.read_text(encoding="utf-8").splitlines())
    return ctx.SourceRoleDecision(object_id, role, status,
                                  (ctx.SourceEvidence(path, "<module>", 1, lines),), "fixture")


def _ledger_failures(decisions, root: Path) -> list[str]:
    failures: list[str] = []
    cells = {(d.object_id, d.role): d for d in decisions if d.status != "DOES_NOT_APPLY"}
    for key in sorted(set(cells) ^ set(LEDGER)):
        failures.append(f"{key}: exception membership differs from ledger")
    for key, (status, facts) in LEDGER.items():
        decision = cells.get(key)
        if decision is None:
            continue
        if decision.status != status:
            failures.append(f"{key}: status {decision.status} differs from ledger {status}")
        cited = {(ev.path, ev.symbol) for ev in decision.evidence}
        for path, symbol, fact in facts:
            if (path, symbol) not in cited:
                failures.append(f"{key}: {path}:{symbol} not cited")
            if re.search(fact, _symbol_text(root / path, symbol)) is None:
                failures.append(f"{key}: fact {fact!r} absent from {path}:{symbol}")
    return failures


def _resolves_to_module(root: Path, dotted: str) -> bool:
    base = root / "src" / dotted.replace(".", "/")
    return base.with_suffix(".py").is_file() or (base / "__init__.py").is_file()


def _external_modules(root: Path) -> dict[str, set[str]]:
    observed: dict[str, set[str]] = {}
    for row in ctx.DOMAIN_CONTEXT_SOURCE_CENSUS:
        tree = ast.parse((root / row.path).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("verifier"):
                for alias in node.names:
                    candidate = f"{node.module}.{alias.name}"
                    module = candidate if _resolves_to_module(root, candidate) else node.module
                    observed.setdefault(module, set()).add(row.path)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("verifier"):
                        observed.setdefault(alias.name, set()).add(row.path)
    census_modules = {row.path[len("src/"):-len(".py")].replace("/", ".")
                      for row in ctx.DOMAIN_CONTEXT_SOURCE_CENSUS}
    return {module: files for module, files in observed.items() if module not in census_modules}


# ---- census, digests and drift -------------------------------------------

def test_census_is_exact_41_paths_sorted_and_unique():
    paths = ctx.DOMAIN_CONTEXT_PATH_CENSUS
    assert len(paths) == 41
    assert paths == tuple(sorted(paths))
    assert len(set(paths)) == 41
    assert all(path.startswith("src/verifier/") for path in paths)


def test_census_matches_disk_line_counts_and_raw_byte_digests():
    for row in ctx.DOMAIN_CONTEXT_SOURCE_CENSUS:
        data = (ROOT / row.path).read_bytes()
        assert len(data.splitlines()) == row.lines, row.path
        assert "sha256:" + hashlib.sha256(data).hexdigest() == row.sha256, row.path
        assert ctx.source_digest(ROOT / row.path) == row.sha256


def test_source_drift_is_empty_for_current_tree():
    assert ctx.source_drift_failures(ROOT) == ()


def test_source_drift_detects_a_changed_byte(tmp_path):
    _copy_census(tmp_path)
    assert ctx.source_drift_failures(tmp_path) == ()
    victim = tmp_path / "src/verifier/domains/env.py"
    victim.write_bytes(victim.read_bytes() + b"\n# drift\n")
    failures = ctx.source_drift_failures(tmp_path)
    assert any(f.startswith("src/verifier/domains/env.py") for f in failures)


def test_source_drift_detects_missing_census_file(tmp_path):
    _copy_census(tmp_path)
    (tmp_path / "src/verifier/domains/role.py").unlink()
    assert any("missing" in failure for failure in ctx.source_drift_failures(tmp_path))


def test_census_row_count_by_primary_kind_matches_batch():
    counts: dict[str, int] = {}
    for spec in ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS:
        counts[spec.primary_kind] = counts.get(spec.primary_kind, 0) + len(spec.owned_paths)
    assert counts == EXPECTED_KIND_COUNTS
    assert sum(counts.values()) == 41


# ---- rows, coverage and the structural oracle -----------------------------

def test_module_rows_match_structural_oracle_and_ledger_specializations():
    assert {s.object_id for s in ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS} == set(EXPECTED_ROWS)
    for object_id, (kind, paths) in EXPECTED_ROWS.items():
        spec = _spec(object_id)
        assert spec.primary_kind == kind
        assert tuple(sorted(spec.owned_paths)) == tuple(sorted(paths))
        ledger_applies = {role for (obj, role), (status, _) in LEDGER.items()
                          if obj == object_id and status == "APPLIES" and role != "VERIFIER"}
        assert set(spec.specializations) == ledger_applies, object_id


def test_primary_kinds_are_the_ten_retained_roots_and_never_object():
    kinds = sorted(s.primary_kind for s in ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS)
    assert kinds == sorted(ctx.PRIMARY_KINDS)
    assert "OBJECT" not in kinds


def test_owned_paths_partition_the_census_exactly():
    owned = [path for spec in ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS for path in spec.owned_paths]
    assert len(owned) == len(set(owned)) == 41
    assert set(owned) == set(ctx.DOMAIN_CONTEXT_PATH_CENSUS)


def test_every_object_decides_all_thirteen_roles_once():
    for spec in ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS:
        roles = [d.role for d in ctx.DOMAIN_CONTEXT_ROLE_DECISIONS if d.object_id == spec.object_id]
        assert sorted(roles) == sorted(ctx.DECIDED_ROLES)
    assert len(ctx.DOMAIN_CONTEXT_ROLE_DECISIONS) == 130


def test_statuses_are_applies_does_not_apply_or_visible_unknown():
    statuses = {d.status for d in ctx.DOMAIN_CONTEXT_ROLE_DECISIONS}
    assert statuses <= {"APPLIES", "DOES_NOT_APPLY", "UNKNOWN"}
    assert statuses == {"APPLIES", "DOES_NOT_APPLY", "UNKNOWN"}


def test_root_role_is_verifier_on_every_row_and_applies():
    for spec in ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS:
        roots = {r.kind: r for r in spec.root_role_decisions}
        assert set(roots) == {"VERIFIER"}
        assert roots["VERIFIER"].status == "APPLIES"
        assert _decision(spec.object_id, "VERIFIER").status == "APPLIES"


def test_specializations_equal_applies_roles_per_object():
    for spec in ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS:
        applies = {d.role for d in ctx.DOMAIN_CONTEXT_ROLE_DECISIONS
                   if d.object_id == spec.object_id and d.status == "APPLIES" and d.role != "VERIFIER"}
        assert set(spec.specializations) == applies


def test_pure_validator_passes_on_the_module_rows():
    ctx.validate_domain_context()


def test_module_has_no_import_of_aggregate_or_domain_catalog():
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    assert "verifier.runtime.package_semantic_ownership" not in imported
    assert "verifier.runtime.package_semantic_ownership_domains" not in imported
    assert all(name.split(".")[0] in {"ast", "dataclasses", "hashlib", "pathlib", "re", "typing", "__future__", "verifier"}
               for name in imported)
    assert imported & {"verifier.runtime.package_semantic_ownership_model"}


def test_hypergraph_boundary_does_not_claim_absent_registry_dispatch():
    boundary = _spec("vstd-hypergraph").consequence_boundary
    assert "no registry dispatch" not in boundary
    assert "current_object_routes" in boundary


# ---- registry and typed layout ------------------------------------------

def test_registry_accumulating_roles_extend_object_and_verifier_is_a_root():
    registry = namespace_registry()
    for role in ctx.ACCUMULATING_ROLES:
        assert registry[role].extends == "OBJECT", role
    assert registry["VERIFIER"].extends is None
    for kind in ctx.PRIMARY_KINDS:
        assert kind in registry, kind


def test_specializations_are_compatible_with_their_primary_kind():
    registry = namespace_registry()
    for spec in ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS:
        for role in spec.specializations:
            assert compatible_specialization(registry, spec.primary_kind, role), (spec.object_id, role)


def test_non_graph_rows_pass_the_real_typed_layout():
    for spec in ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS:
        if spec.primary_kind == "GRAPH":
            continue
        operands = {name: targets for name, targets in spec.operands}
        item = NamespaceObject.create(spec.object_id, ObjectKind(spec.primary_kind), {}, operands)
        validate_object_layout(item)


def test_graph_missing_element_kind_fails_for_its_own_reason():
    item = NamespaceObject.create(
        "vstd-package-graph", ObjectKind.GRAPH, {"representation_role": "package-graph"},
        {"members": ("vstd-environment",)},
    )
    with pytest.raises(ValueError, match=r"^None is not a valid ObjectKind$"):
        validate_object_layout(item)


def test_graph_missing_members_fails_for_its_own_reason():
    item = NamespaceObject.create(
        "vstd-package-graph", ObjectKind.GRAPH,
        {"representation_role": "package-graph", "element_kind": "ENV"}, {},
    )
    with pytest.raises(ValueError, match=r"^typed graph requires nonempty bound members$"):
        validate_object_layout(item)


def test_graph_layout_is_an_open_blocker_not_a_silent_exemption():
    graph = _spec("vstd-package-graph")
    assert graph.operands == ()
    assert any("GRAPH" in text for text in ctx.open_blockers())


def test_owner_asset_obligations_remain_open_blockers():
    text = " ".join(ctx.open_blockers())
    for obligation in ("ASSET-0.1-identity-and-quantity", "ASSET-0.2-issuance-and-redemption",
                       "ASSET-0.3-custody-and-encumbrance"):
        assert obligation in text, obligation


# ---- external evidence dependencies -------------------------------------

def test_every_external_evidence_dependency_is_census_owned_or_declared():
    observed = _external_modules(ROOT)
    declared = ctx.EXTERNAL_EVIDENCE_DEPENDENCIES
    assert set(observed) == set(declared), (sorted(set(observed) - set(declared)),
                                            sorted(set(declared) - set(observed)))
    for module, (klass, reason) in declared.items():
        assert klass in {"ROUTE_REGISTRY", "EVIDENCE_SELECTION", "EVIDENCE_PRODUCER",
                         "SOURCE_BINDING", "CORE_LIBRARY"}, module
        assert reason, module
    assert declared["verifier.domains.contracts.current_object_routes"][0] == "ROUTE_REGISTRY"


def test_undeclared_external_import_is_detected_in_fixture(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/env.py"
    victim.write_text(victim.read_text(encoding="utf-8")
                      + "\nfrom verifier.domains.contracts import bench_checks\n", encoding="utf-8")
    (tmp_path / "src/verifier/domains/contracts/bench_checks.py").write_text("VALUE = 1\n", encoding="utf-8")
    assert "verifier.domains.contracts.bench_checks" in _external_modules(tmp_path)


def test_external_module_resolution_uses_the_audited_root_not_the_repository(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/env.py"
    victim.write_text(victim.read_text(encoding="utf-8")
                      + "\nfrom verifier.domains.contracts import bench_checks\n", encoding="utf-8")
    # The repository has bench_checks.py, but the audited root does not: the import binds the package.
    assert not (tmp_path / "src/verifier/domains/contracts/bench_checks.py").exists()
    assert (ROOT / "src/verifier/domains/contracts/bench_checks.py").is_file()
    observed = _external_modules(tmp_path)
    assert "verifier.domains.contracts.bench_checks" not in observed
    assert "verifier.domains.contracts" in observed


# ---- root manifest admission cross-check (read-only) ----------------------

@pytest.mark.skipif(not ROOT_MANIFEST.is_file(), reason="root objects.vstd not present")
def test_root_manifest_admits_each_object_kind_and_operand_targets():
    manifest = json.loads(ROOT_MANIFEST.read_text(encoding="utf-8"))
    by_id = {entry["object_id"]: entry for entry in manifest["namespace"]["objects"]}
    for object_id, (kind, _paths) in EXPECTED_ROWS.items():
        assert object_id in by_id, object_id
        assert by_id[object_id]["kind"] == kind, object_id
    for spec in ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS:
        if spec.primary_kind == "GRAPH":
            continue
        root_operands = by_id[spec.object_id].get("operands") or {}
        assert {name: tuple(sorted(targets)) for name, targets in root_operands.items()} == {
            name: tuple(sorted(targets)) for name, targets in spec.operands
        }, spec.object_id


@pytest.mark.skipif(not ROOT_MANIFEST.is_file(), reason="root objects.vstd not present")
def test_root_manifest_digests_agree_with_census():
    manifest = json.loads(ROOT_MANIFEST.read_text(encoding="utf-8"))
    recorded = {}
    for entry in manifest["namespace"]["objects"]:
        for paths in (entry.get("classification") or {}).values():
            for ev in paths.get("evidence", []):
                recorded[ev["path"]] = ev["sha256"]
    for row in ctx.DOMAIN_CONTEXT_SOURCE_CENSUS:
        assert recorded.get(row.path) == row.sha256, row.path


# ---- source-bound ledger, executable gates and positive controls ----------

def test_exception_ledger_matches_module_cells_and_live_source():
    assert _ledger_failures(ctx.DOMAIN_CONTEXT_ROLE_DECISIONS, ROOT) == []


def test_no_expected_table_is_the_sole_oracle(tmp_path):
    decisions = list(ctx.DOMAIN_CONTEXT_ROLE_DECISIONS)
    index = next(i for i, d in enumerate(decisions)
                 if d.object_id == "vstd-environment" and d.role == "SENSOR")
    decisions[index] = dataclasses.replace(
        decisions[index], status="APPLIES",
        evidence=(ctx.SourceEvidence("src/verifier/domains/contracts/env_checks.py", "mechanism_digest", 106, 112),),
    )
    failures = _ledger_failures(tuple(decisions), ROOT)
    assert any("vstd-environment" in failure and "SENSOR" in failure for failure in failures)

    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/contracts/event_dispatch.py"
    victim.write_text(victim.read_text(encoding="utf-8")
                      .replace("not in topic_of", "in topic_of")
                      .replace("pair not in pending", "pair in pending"), encoding="utf-8")
    failures = _ledger_failures(ctx.DOMAIN_CONTEXT_ROLE_DECISIONS, tmp_path)
    assert any("vstd-event" in failure and "PROTOCOL" in failure for failure in failures)


def test_module_evidence_is_clean_on_current_tree():
    assert ctx.evidence_failures(ROOT) == ()


def test_positive_control_copy_has_no_evidence_failures(tmp_path):
    _copy_census(tmp_path)
    assert ctx.evidence_failures(tmp_path) == ()


def test_fixed_subprocess_socket_and_file_calls_are_not_actuation(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/contracts/event_closure.py"
    victim.write_text(victim.read_text(encoding="utf-8") + (
        "\nimport socket\nimport subprocess\nfrom pathlib import Path\n\n\n"
        "def _generic_effects(path):\n"
        "    subprocess.run(['true'])\n"
        "    socket.create_connection(('127.0.0.1', 1))\n"
        "    Path(path).write_text('x', encoding='utf-8')\n"
        "    return getattr(Path, 'name')\n"
    ), encoding="utf-8")
    assert _refutations(ctx.evidence_failures(tmp_path)) == []


def test_refutation_fixture_with_dynamic_getattr_breaks_actuator_absence(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/contracts/event_closure.py"
    victim.write_text(victim.read_text(encoding="utf-8") + "\ndef _route(module, name):\n    return getattr(module, name)\n", encoding="utf-8")
    decision = _whole_module_decision("vstd-event", "ACTUATOR", "DOES_NOT_APPLY",
                                      "src/verifier/domains/contracts/event_closure.py", victim)
    failures = ctx.evidence_failures(tmp_path, (decision,))
    assert any("ACTUATOR" in failure for failure in failures)


def test_runtime_key_lookup_into_route_registry_refutes_actuator_dna(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/contracts/event_dispatch.py"
    victim.write_text(ROUTE_LOOKUP, encoding="utf-8")
    decision = _whole_module_decision("vstd-event", "ACTUATOR", "DOES_NOT_APPLY",
                                      "src/verifier/domains/contracts/event_dispatch.py", victim)
    failures = ctx.evidence_failures(tmp_path, (decision,))
    assert any("ACTUATOR" in failure for failure in failures)


def test_hyper_unknown_absorption_dispatches_a_data_chosen_coordinate():
    decision = _decision("vstd-hypergraph", "ACTUATOR")
    assert decision.status == "APPLIES"
    assert [(ev.path, ev.symbol) for ev in decision.evidence] == [
        (CONTRACTS + "hyper_unknown_absorption.py", "bound_children")]


def test_sensor_read_bytes_alone_is_never_applies_and_acquisition_is(tmp_path):
    for spec in ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS:
        assert _decision(spec.object_id, "SENSOR").status != "APPLIES", spec.object_id

    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/env.py"
    victim.write_text(SENSOR_READ_ONLY, encoding="utf-8")
    read_only = _fixture_decision("vstd-environment", "SENSOR", "APPLIES",
                                  "src/verifier/domains/env.py", "evaluate", victim)
    assert any("SENSOR" in failure for failure in ctx.evidence_failures(tmp_path, (read_only,)))

    victim.write_text(SENSOR_ACQUISITION, encoding="utf-8")
    acquired = _fixture_decision("vstd-environment", "SENSOR", "APPLIES",
                                 "src/verifier/domains/env.py", "evaluate", victim)
    assert ctx.evidence_failures(tmp_path, (acquired,)) == ()


def test_declared_measurand_cannot_be_measurement_dna(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/contracts/event_dispatch.py"
    victim.write_text(MEASURAND_DECLARED, encoding="utf-8")
    decision = _whole_module_decision("vstd-event", "MEASUREMENT", "DOES_NOT_APPLY",
                                      "src/verifier/domains/contracts/event_dispatch.py", victim)
    assert any("MEASUREMENT" in failure for failure in ctx.evidence_failures(tmp_path, (decision,)))


def test_measurement_dna_requires_exact_source_refutation():
    for object_id in ("vstd-hypergraph", "vstd-identity"):
        assert _decision(object_id, "MEASUREMENT").status != "APPLIES", object_id
    assert _decision("vstd-environment", "MEASUREMENT").status == "UNKNOWN"
    for decision in ctx.DOMAIN_CONTEXT_ROLE_DECISIONS:
        if decision.role == "MEASUREMENT" and decision.status == "DOES_NOT_APPLY":
            assert "residual judgment" not in decision.reason, decision.object_id
            assert any(Path(ev.path).name in decision.reason for ev in decision.evidence), decision.object_id


def _refutations(failures):
    """Role verdict failures only: a changed whole-file citation reports drift, which is separate."""
    return [failure for failure in failures if "module span is not whole-file" not in failure]


def test_event_protocol_applies_rests_on_the_live_ordering_predicates(tmp_path):
    protocol = _decision("vstd-event", "PROTOCOL")
    assert {ev.symbol for ev in protocol.evidence} == {"_replay_log"}
    assert ctx.evidence_failures(ROOT) == ()

    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/contracts/event_dispatch.py"
    text = victim.read_text(encoding="utf-8")
    # Two of the three ordering predicates go; the ack-before-dispatch predicate on the
    # ``(event, handler) not in pending`` line still orders the replay, so APPLIES stands.
    partial = text.replace("if event not in topic_of:", "if False:").replace("if pair not in pending:", "if False:")
    assert partial != text
    victim.write_text(partial, encoding="utf-8")
    assert not any(f.startswith("vstd-event PROTOCOL") for f in ctx.evidence_failures(tmp_path))

    removed = partial.replace(
        "if (event, handler) not in acknowledged and (event, handler) not in pending:", "if False:")
    assert removed != partial
    victim.write_text(removed, encoding="utf-8")
    failures = ctx.evidence_failures(tmp_path)
    assert any(f.startswith("vstd-event PROTOCOL") and "no live PROTOCOL test" in f for f in failures), failures


def test_gate_normalization_ignores_prose_comments_and_declared_non_claims():
    prose = "CLAIM = \"physical clock identity, calibration or wall-clock truth is not established\"\n"
    declared = "LABELS = {\"clock_calibration\": \"NOT_ESTABLISHED\"}\n"
    key = "CALIBRATION = {\"calibration\": 1}\n"
    prose_acquisition = "NOTE = \"adc.convert(channel) and subprocess.run(argv) are described here only\"\n"
    commented = "# adc.convert(channel)\nVALUE = 1\n"
    assert ctx.gate_hits("SENSOR", prose) == ()
    assert ctx.gate_hits("SENSOR", declared) == ()
    assert ctx.gate_hits("SENSOR", key) == ()
    assert ctx.gate_hits("SENSOR", prose_acquisition) == ()
    assert ctx.gate_hits("SENSOR", commented) == ()
    assert ctx.gate_hits("SENSOR", "SAMPLE = adc.convert(channel)\n") != ()


def test_keyword_and_local_renames_do_not_change_the_registry_dispatch(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/contracts/hyper_unknown_absorption.py"
    original = victim.read_text(encoding="utf-8")
    assert "objective=selection[\"coordinate\"]" in original
    renamed = original.replace("objective=selection[\"coordinate\"]", "target_coordinate=selection[\"coordinate\"]")
    victim.write_text(renamed, encoding="utf-8")
    assert _refutations(ctx.evidence_failures(tmp_path)) == []
    victim.write_text(re.sub(r"\bselection\b", "picked", original), encoding="utf-8")
    assert _refutations(ctx.evidence_failures(tmp_path)) == []


def test_fixed_coordinate_removes_hyper_actuator_applies(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/contracts/hyper_unknown_absorption.py"
    original = victim.read_text(encoding="utf-8")
    fixed = original.replace("objective=selection[\"coordinate\"]", "objective=\"fixed-coordinate\"")
    assert fixed != original
    victim.write_text(fixed, encoding="utf-8")
    failures = ctx.evidence_failures(tmp_path)
    assert any(failure.startswith("vstd-hypergraph ACTUATOR") for failure in failures), failures


def test_dead_dispatch_cannot_establish_actuator_applies(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/contracts/hyper_unknown_absorption.py"
    original = victim.read_text(encoding="utf-8")
    dead = original.replace("objective=selection[\"coordinate\"]", "objective=\"fixed-coordinate\"")
    import_line = "    from verifier.domains.contracts import current_object_routes as routes\n"
    assert dead.count(import_line) == 1
    dead = dead.replace(import_line, (
        "    if False:\n"
        "        routes.replay_current_object_certificate(b\"\", objective=selection[\"coordinate\"])\n"
    ) + import_line, 1)
    victim.write_text(dead, encoding="utf-8")
    failures = ctx.evidence_failures(tmp_path)
    assert any(failure.startswith("vstd-hypergraph ACTUATOR") and "no live" in failure
               for failure in failures), failures


def test_dead_dispatch_still_refutes_absence_fail_closed(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/contracts/event_closure.py"
    victim.write_text(victim.read_text(encoding="utf-8") + (
        "\n\nfrom verifier.domains.contracts import current_object_routes as routes\n\n\n"
        "def _dead_route(request):\n"
        "    return None\n"
        "    routes.replay_current_object_certificate(b\"\", coordinate=request[\"coordinate\"])\n"
    ), encoding="utf-8")
    failures = ctx.evidence_failures(tmp_path)
    assert any(failure.startswith("vstd-event ACTUATOR") for failure in failures), failures


def test_data_chosen_registry_dispatch_refutes_actuator_absence(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/contracts/event_closure.py"
    victim.write_text(victim.read_text(encoding="utf-8") + (
        "\n\nfrom verifier.domains.contracts import current_object_routes as routes\n\n\n"
        "def _dispatch(request, children):\n"
        "    return [routes.replay_current_object_certificate(child, coordinate=request[\"coordinate\"])\n"
        "            for child in children]\n"
    ), encoding="utf-8")
    failures = ctx.evidence_failures(tmp_path)
    assert any(failure.startswith("vstd-event ACTUATOR") for failure in failures), failures


def test_adc_convert_mutant_invalidates_sensor_absence(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/env.py"
    victim.write_text(victim.read_text(encoding="utf-8") + (
        "\n\ndef _sample_channel(adc, channel):\n    return adc.convert(channel)\n"
    ), encoding="utf-8")
    failures = ctx.evidence_failures(tmp_path)
    assert any(failure.startswith("vstd-environment SENSOR") for failure in failures), failures


def test_acquisition_without_calibration_path_is_not_sensor_applies(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/env.py"
    victim.write_text("def evaluate(adc, channel):\n    return adc.convert(channel)\n", encoding="utf-8")
    decision = _fixture_decision("vstd-environment", "SENSOR", "APPLIES",
                                 "src/verifier/domains/env.py", "evaluate", victim)
    failures = ctx.evidence_failures(tmp_path, (decision,))
    assert any("lacks a calibration" in failure for failure in failures), failures


def test_prose_mentioning_mechanisms_does_not_refute_absence(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/env.py"
    victim.write_text(victim.read_text(encoding="utf-8") + (
        "\n\n# adc.convert(channel) and subprocess.run and _ROUTES[coordinate] are prose here\n"
        "NOTE = \"the adc.convert(channel) call and getattr(module, name) are not made by this file\"\n"
    ), encoding="utf-8")
    assert _refutations(ctx.evidence_failures(tmp_path)) == []


def test_fixed_route_and_non_constant_getattr_are_distinguished(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/contracts/event_closure.py"
    victim.write_text(victim.read_text(encoding="utf-8") + (
        "\n\ndef _fixed(module):\n    return getattr(module, 'name')\n"), encoding="utf-8")
    assert _refutations(ctx.evidence_failures(tmp_path)) == []


# ---- adversarial validator mutations --------------------------------------

def test_role_promotion_without_specialization_is_rejected():
    decisions = list(ctx.DOMAIN_CONTEXT_ROLE_DECISIONS)
    index = next(i for i, d in enumerate(decisions) if d.object_id == "vstd-time" and d.role == "ASSET")
    decisions[index] = dataclasses.replace(decisions[index], status="APPLIES",
                                           evidence=(ctx.SourceEvidence("src/verifier/domains/contracts/time_closure.py", "_evaluate", 415, 456),))
    with pytest.raises(ValueError, match="DOMAIN_CONTEXT_SPECIALIZATION"):
        _validate(decisions=tuple(decisions))


def test_applies_with_whole_module_evidence_is_rejected():
    decisions = list(ctx.DOMAIN_CONTEXT_ROLE_DECISIONS)
    index = next(i for i, d in enumerate(decisions) if d.object_id == "vstd-identity" and d.role == "PROTOCOL")
    decisions[index] = dataclasses.replace(
        decisions[index],
        evidence=(ctx.SourceEvidence("src/verifier/domains/contracts/identity_presentation.py", "<module>", 1, 1056),),
    )
    with pytest.raises(ValueError, match="DOMAIN_CONTEXT_APPLIES_EVIDENCE"):
        _validate(decisions=tuple(decisions))


def test_does_not_apply_with_symbol_evidence_is_rejected():
    decisions = list(ctx.DOMAIN_CONTEXT_ROLE_DECISIONS)
    index = next(i for i, d in enumerate(decisions) if d.object_id == "vstd-time" and d.role == "ASSET")
    decisions[index] = dataclasses.replace(
        decisions[index],
        evidence=(ctx.SourceEvidence("src/verifier/domains/contracts/time_closure.py", "_evaluate", 415, 456),),
    )
    with pytest.raises(ValueError, match="DOMAIN_CONTEXT_DNA_EVIDENCE"):
        _validate(decisions=tuple(decisions))


def test_unknown_is_visible_and_blocks_aggregation():
    unknown_cells = {key for key, (status, _) in LEDGER.items() if status == "UNKNOWN"}
    assert unknown_cells
    visible = {(d.object_id, d.role) for d in ctx.unknown_decisions()}
    assert visible == unknown_cells
    blockers = ctx.aggregation_blockers()
    for object_id, role in unknown_cells:
        assert any(object_id in blocker and role in blocker and "UNKNOWN" in blocker for blocker in blockers)
    with pytest.raises(ValueError, match="^DOMAIN_CONTEXT_AGGREGATION_BLOCKED"):
        ctx.require_aggregation_ready()
    counts = ctx.decision_counts()
    assert counts["UNKNOWN"] == len(unknown_cells)
    assert counts["APPLIES"] + counts["DOES_NOT_APPLY"] + counts["UNKNOWN"] == 130
    assert counts["APPLIES"] == sum(1 for status, _ in LEDGER.values() if status == "APPLIES")


def test_unknown_never_enters_specializations():
    for decision in ctx.unknown_decisions():
        assert decision.role not in _spec(decision.object_id).specializations
    specs = list(ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS)
    index = next(i for i, s in enumerate(specs) if s.object_id == "vstd-identity")
    specs[index] = dataclasses.replace(specs[index], specializations=tuple(sorted(
        specs[index].specializations + ("CONTROLLER",))))
    with pytest.raises(ValueError, match="DOMAIN_CONTEXT_UNKNOWN_SPECIALIZATION"):
        _validate(specs=tuple(specs))


def test_unknown_without_a_cited_signal_is_rejected(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/env.py"
    victim.write_text("def evaluate(value):\n    return value\n", encoding="utf-8")
    unknown = _fixture_decision("vstd-environment", "MEASUREMENT", "UNKNOWN",
                                "src/verifier/domains/env.py", "evaluate", victim)
    assert any("UNKNOWN cites no MEASUREMENT signal" in failure
               for failure in ctx.evidence_failures(tmp_path, (unknown,)))


def test_unknown_requires_repository_specific_reason():
    decisions = list(ctx.DOMAIN_CONTEXT_ROLE_DECISIONS)
    index = next(i for i, d in enumerate(decisions) if d.object_id == "vstd-identity" and d.role == "CONTROLLER")
    decisions[index] = dataclasses.replace(decisions[index], reason="residual judgment")
    with pytest.raises(ValueError, match="DOMAIN_CONTEXT_REASON"):
        _validate(decisions=tuple(decisions))


def test_missing_role_decision_is_rejected():
    decisions = tuple(d for d in ctx.DOMAIN_CONTEXT_ROLE_DECISIONS
                      if not (d.object_id == "vstd-space" and d.role == "TRANSACTION"))
    with pytest.raises(ValueError, match="DOMAIN_CONTEXT_DECISION_COVERAGE"):
        _validate(decisions=decisions)


def test_object_primary_kind_is_rejected():
    specs = list(ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS)
    index = next(i for i, s in enumerate(specs) if s.object_id == "vstd-time")
    specs[index] = dataclasses.replace(specs[index], primary_kind="OBJECT")
    with pytest.raises(ValueError, match="DOMAIN_CONTEXT"):
        _validate(specs=tuple(specs))


def test_duplicate_owned_path_is_rejected():
    specs = list(ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS)
    index = next(i for i, s in enumerate(specs) if s.object_id == "vstd-role")
    duplicated = specs[index].owned_paths + ("src/verifier/domains/role.py",)
    specs[index] = dataclasses.replace(specs[index], owned_paths=duplicated)
    with pytest.raises(ValueError, match="DOMAIN_CONTEXT"):
        _validate(specs=tuple(specs))


def test_missing_owned_path_is_rejected():
    specs = list(ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS)
    index = next(i for i, s in enumerate(specs) if s.object_id == "vstd-role")
    specs[index] = dataclasses.replace(specs[index], owned_paths=specs[index].owned_paths[:-1])
    with pytest.raises(ValueError, match="DOMAIN_CONTEXT"):
        _validate(specs=tuple(specs))


def test_extra_owned_path_outside_census_is_rejected():
    specs = list(ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS)
    index = next(i for i, s in enumerate(specs) if s.object_id == "vstd-role")
    extra = specs[index].owned_paths + ("src/verifier/domains/not_admitted.py",)
    specs[index] = dataclasses.replace(specs[index], owned_paths=extra)
    with pytest.raises(ValueError, match="DOMAIN_CONTEXT"):
        _validate(specs=tuple(specs))


def test_wrong_owner_evidence_is_rejected():
    decisions = list(ctx.DOMAIN_CONTEXT_ROLE_DECISIONS)
    index = next(i for i, d in enumerate(decisions) if d.object_id == "vstd-time" and d.role == "POLICY")
    decisions[index] = dataclasses.replace(
        decisions[index],
        evidence=(ctx.SourceEvidence("src/verifier/domains/contracts/space_closure.py", "_evaluate", 175, 245),),
    )
    with pytest.raises(ValueError, match="DOMAIN_CONTEXT_EVIDENCE_OWNER"):
        _validate(decisions=tuple(decisions))


def test_verifier_root_row_must_match_the_table():
    specs = list(ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS)
    index = next(i for i, s in enumerate(specs) if s.object_id == "vstd-owner")
    roots = tuple(dataclasses.replace(r, reason="stale reason") for r in specs[index].root_role_decisions)
    specs[index] = dataclasses.replace(specs[index], root_role_decisions=roots)
    with pytest.raises(ValueError, match="DOMAIN_CONTEXT_ROOT_ROLE"):
        _validate(specs=tuple(specs))


def test_operand_slots_must_match_typed_layout():
    specs = list(ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS)
    index = next(i for i, s in enumerate(specs) if s.object_id == "vstd-owner")
    operands = (("actor", ("vstd-actor",)),)
    specs[index] = dataclasses.replace(specs[index], operands=operands)
    with pytest.raises(ValueError, match="DOMAIN_CONTEXT_OPERAND"):
        _validate(specs=tuple(specs))


def test_digest_mismatch_in_census_is_rejected():
    census = list(ctx.DOMAIN_CONTEXT_SOURCE_CENSUS)
    row = census[0]
    census[0] = dataclasses.replace(row, sha256="sha256:" + "0" * 64)
    with pytest.raises(ValueError, match="DOMAIN_CONTEXT_DIGEST_COVERAGE"):
        _validate(census=tuple(census))


def test_docstring_only_span_is_rejected(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/env.py"
    victim.write_text(
        '"""Module doc."""\n\n\ndef evaluate(value):\n'
        '    """Docstring-only evidence.\n\n    platform.system() appears only in prose here.\n    """\n'
        "    return value\n",
        encoding="utf-8",
    )
    start, end = _docstring_span(victim.read_text(encoding="utf-8"), "evaluate")
    decision = dataclasses.replace(
        _decision("vstd-environment", "POLICY"),
        evidence=(ctx.SourceEvidence("src/verifier/domains/env.py", "evaluate", start, end),),
    )
    failures = ctx.evidence_failures(tmp_path, (decision,))
    assert any("docstring or comment" in failure for failure in failures)


def test_comment_only_span_is_rejected(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/env.py"
    victim.write_text(
        "def evaluate(value):\n"
        "    # platform.system() appears only in this comment\n"
        "    return value\n",
        encoding="utf-8",
    )
    line = 2
    decision = dataclasses.replace(
        _decision("vstd-environment", "POLICY"),
        evidence=(ctx.SourceEvidence("src/verifier/domains/env.py", "evaluate", line, line),),
    )
    failures = ctx.evidence_failures(tmp_path, (decision,))
    assert any("docstring or comment" in failure for failure in failures)


def test_span_outside_symbol_is_reported(tmp_path):
    _copy_census(tmp_path)
    decision = dataclasses.replace(
        _decision("vstd-environment", "POLICY"),
        evidence=(ctx.SourceEvidence("src/verifier/domains/env.py", "collect_configuration", 9, 200),),
    )
    failures = ctx.evidence_failures(tmp_path, (decision,))
    assert any("outside symbol" in failure for failure in failures)


def test_missing_symbol_is_reported(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/env.py"
    victim.write_text("def other():\n    return 1\n", encoding="utf-8")
    failures = ctx.evidence_failures(tmp_path)
    assert any("symbol missing" in failure for failure in failures)


# ---- source-specific cells, sidecars and batch-local root mode -------------

def test_role_policy_span_is_the_policy_admission_path():
    decision = _decision("vstd-role", "POLICY")
    assert decision.status == "APPLIES"
    assert [(ev.path, ev.symbol) for ev in decision.evidence] == [
        (CONTRACTS + "role_constraints.py", "_policy")]
    source = (ROOT / (CONTRACTS + "role_constraints.py")).read_text(encoding="utf-8")
    assert (decision.evidence[0].start_line, decision.evidence[0].end_line) == _span_of(source, "_policy")
    assert "retained_selection.policy" in _symbol_text(ROOT / CONTRACTS / "role_constraints.py", "_policy")


def test_retained_elapsed_ms_is_unknown_and_never_lexical_dne():
    decision = _decision("vstd-receipt", "MEASUREMENT")
    assert decision.status == "UNKNOWN"
    assert [(ev.path, ev.symbol) for ev in decision.evidence] == [
        (CONTRACTS + "receipt_statics.py", "_execution")]
    assert "elapsed_ms" in _symbol_text(ROOT / CONTRACTS / "receipt_statics.py", "_execution")
    assert ctx.evidence_failures(ROOT) == ()


def test_declared_latency_measurand_with_units_and_method_is_measurement_applies(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/contracts/receipt_statics.py"
    victim.write_text(victim.read_text(encoding="utf-8") + (
        "\n\nLATENCY = {\"phenomenon\": \"command latency\", \"method\": \"perf_counter\", \"clock\": \"monotonic\", "
        "\"units\": \"milliseconds\", \"uncertainty\": \"0.1\", \"missingness\": \"NaN\"}\n"
        "def measure_latency(run):\n"
        "    return LATENCY\n"
    ), encoding="utf-8")
    decision = _whole_module_decision("vstd-receipt", "MEASUREMENT", "APPLIES",
                                      "src/verifier/domains/contracts/receipt_statics.py", victim)
    assert ctx.evidence_failures(tmp_path, (decision,)) == ()


def test_latency_key_without_declaration_is_not_measurement_applies(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/contracts/receipt_statics.py"
    decision = _fixture_decision("vstd-receipt", "MEASUREMENT", "APPLIES",
                                 "src/verifier/domains/contracts/receipt_statics.py", "_execution", victim)
    failures = ctx.evidence_failures(tmp_path, (decision,))
    assert any("lacks a declared phenomenon" in failure for failure in failures), failures


def test_identity_controller_witness_alone_is_not_a_controller():
    assert ctx._requirement_gap("CONTROLLER", frozenset({"controller_id", "terminal_controller"})) is not None
    assert ctx._requirement_gap("CONTROLLER", frozenset({"submitted_action", "observed"})) is None
    decision = _decision("vstd-identity", "CONTROLLER")
    assert decision.status == "UNKNOWN"
    assert ctx.evidence_failures(ROOT) == ()


def test_unknown_satisfying_applies_requirement_must_be_promoted(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/contracts/identity_presentation.py"
    victim.write_text(victim.read_text(encoding="utf-8") + (
        "\n\ndef _directed(observed):\n"
        "    submitted_action = {\"directed_action\": observed, \"feedback\": True}\n"
        "    return submitted_action\n"
    ), encoding="utf-8")
    unknown = _fixture_decision("vstd-identity", "CONTROLLER", "UNKNOWN",
                                "src/verifier/domains/contracts/identity_presentation.py", "_directed", victim)
    failures = ctx.evidence_failures(tmp_path, (unknown,))
    assert failures == (
        "vstd-identity CONTROLLER: src/verifier/domains/contracts/identity_presentation.py:_directed "
        "satisfies the APPLIES requirement; promote the cell",), failures


def test_root_role_modes_are_batch_local_and_exported_only_when_representable():
    assert set(ctx.ROOT_ROLE_MODES) == {spec.object_id for spec in ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS}
    assert set(ctx.ROOT_ROLE_MODES.values()) <= {"APPLIES", "DOES_NOT_APPLY", "UNKNOWN"}
    for spec in ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS:
        assert _decision(spec.object_id, "VERIFIER").status == ctx.ROOT_ROLE_MODES[spec.object_id]
        assert {r.kind for r in spec.root_role_decisions} == {"VERIFIER"}


def test_unknown_root_mode_cannot_export_a_root_role_decision(monkeypatch):
    decisions = list(ctx.DOMAIN_CONTEXT_ROLE_DECISIONS)
    index = next(i for i, d in enumerate(decisions) if d.object_id == "vstd-time" and d.role == "VERIFIER")
    decisions[index] = dataclasses.replace(decisions[index], status="UNKNOWN")
    modes = dict(ctx.ROOT_ROLE_MODES, **{"vstd-time": "UNKNOWN"})
    monkeypatch.setattr(ctx, "ROOT_ROLE_MODES", modes)
    with pytest.raises(ValueError, match="exports an UNKNOWN root the shared model cannot represent"):
        _validate(decisions=tuple(decisions))
    # Without the export, an UNKNOWN root is honest: the table carries it and the mode matches.
    specs = tuple(
        dataclasses.replace(spec, root_role_decisions=())
        if spec.object_id == "vstd-time" else spec
        for spec in ctx.DOMAIN_CONTEXT_OWNERSHIP_SPECS
    )
    _validate(specs=specs, decisions=tuple(decisions))


def test_root_mode_mismatch_with_table_is_rejected(monkeypatch):
    modes = dict(ctx.ROOT_ROLE_MODES, **{"vstd-time": "UNKNOWN"})
    monkeypatch.setattr(ctx, "ROOT_ROLE_MODES", modes)
    with pytest.raises(ValueError, match="DOMAIN_CONTEXT_ROOT_ROLE"):
        _validate()


def test_does_not_apply_reasons_are_source_specific_not_template_or_filename_lists():
    dna = [d for d in ctx.DOMAIN_CONTEXT_ROLE_DECISIONS if d.status == "DOES_NOT_APPLY"]
    assert len(dna) == 99
    assert len({d.reason for d in dna}) == len(dna)
    for decision in dna:
        assert "gate matches" not in decision.reason, (decision.object_id, decision.role)
        assert "AST scan" in decision.reason, (decision.object_id, decision.role)
        assert ctx.ROLE_TESTS[decision.role] in decision.reason
        assert ctx._OBJECT_FACTS[decision.object_id] in decision.reason
        assert len(decision.reason) > 250, (decision.object_id, decision.role)


def test_applies_and_unknown_reasons_name_their_symbol_and_fact():
    for decision in ctx.DOMAIN_CONTEXT_ROLE_DECISIONS:
        if decision.status == "DOES_NOT_APPLY":
            continue
        for ev in decision.evidence:
            if ev.symbol == "<module>":
                continue
            assert ev.symbol in decision.reason or decision.role == "VERIFIER", (decision.object_id, decision.role)


def test_registry_dispatch_is_only_defined_by_declared_route_registry():
    assert ctx._REGISTRY_MODULES == ("verifier.domains.contracts.current_object_routes",)
    assert ctx.EXTERNAL_EVIDENCE_DEPENDENCIES["verifier.domains.contracts.current_object_routes"][0] == "ROUTE_REGISTRY"


def test_latency_quantity_without_time_base_is_not_measurement_applies(tmp_path):
    _copy_census(tmp_path)
    victim = tmp_path / "src/verifier/domains/contracts/receipt_statics.py"
    victim.write_text(victim.read_text(encoding="utf-8") + (
        "\n\nLATENCY = {\"phenomenon\": \"command latency\", \"method\": \"perf_counter\", "
        "\"units\": \"milliseconds\", \"uncertainty\": \"0.1\", \"missingness\": \"NaN\", \"elapsed_ms\": 1.0}\n"
        "def measure_latency(run):\n"
        "    return LATENCY\n"
    ), encoding="utf-8")
    decision = _whole_module_decision("vstd-receipt", "MEASUREMENT", "APPLIES",
                                      "src/verifier/domains/contracts/receipt_statics.py", victim)
    failures = ctx.evidence_failures(tmp_path, (decision,))
    assert failures == ("vstd-receipt MEASUREMENT: src/verifier/domains/contracts/receipt_statics.py:<module> "
                        "lacks a declared time base for the latency quantity",), failures
