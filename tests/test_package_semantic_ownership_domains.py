# Terminology: abstract syntax tree (AST).
from __future__ import annotations

import ast
import copy
import hashlib
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from verifier.core.namespace import ObjectKind
from verifier.runtime.namespace_contracts import namespace_registry
from verifier.runtime.package_semantic_ownership_domains import (
    DOMAIN_OWNERSHIP_SPECS,
    canonical_executable_ast,
    canonical_executable_ast_sha256,
)


ROOT = Path(__file__).parents[1]
SRC = ROOT / "src"
OBJECT_INVENTORY_PATH = "src/verifier/domains/inventory.py"
OBJECT_INVENTORY_BYTES = 236097
OBJECT_INVENTORY_SHA256 = (
    "13667a264342d4e5c1ee53ba08195277c3ec06b12268fd1ffcd5a159da7a2694"
)
# Golden for canonical_executable_ast_sha256; the same digest must be produced
# by every interpreter listed in PROBE_INTERPRETERS_ENV.
OBJECT_INVENTORY_CANONICAL_EXECUTABLE_AST_SHA256 = (
    "b7529ac824838b7cee78bc693b0dfdd5f44cc75339e3b54c73a1fc2f6f413a4e"
)
PROBE_INTERPRETERS_ENV = "VERIFIER_AST_PROBE_PYTHONS"

# Primary kind, accumulated additional roles, operands, and exact path owner.
EXPECTED = {
    "vstd-domains-package-marker": (
        "ARCH", (), (), ("src/verifier/domains/__init__.py",),
    ),
    "vstd-domain-carrier-protocols": (
        "PROTOCOL", ("MEASUREMENT", "POLICY"), (),
        ("src/verifier/domains/carriers.py",),
    ),
    "vstd-domain-specification-catalog": (
        "POLICY", ("MEASUREMENT", "SENSOR"), (),
        ("src/verifier/domains/catalog.py",),
    ),
    "vstd-domain-certificate-engine": (
        "VERIFIER", ("ACTUATOR", "MEASUREMENT", "POLICY", "SENSOR", "TRANSACTION"), (),
        ("src/verifier/domains/certification.py",),
    ),
    "vstd-domain-checking-primitives": (
        "VERIFIER", ("POLICY",), (), ("src/verifier/domains/common.py",),
    ),
    "vstd-domain-contracts-package-marker": (
        "ARCH", (), (), ("src/verifier/domains/contracts/__init__.py",),
    ),
    "vstd-object-obligation-inventory": (
        "POLICY", (), (), ("src/verifier/domains/inventory.py",),
    ),
    "vstd-mainstay-certificate-engine": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/domains/mainstay_certification.py",),
    ),
    "vstd-mainstay-evaluator": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/domains/mainstays.py",),
    ),
    "vstd-retained-model-training-arithmetic": (
        "VERIFIER", ("MEASUREMENT", "POLICY"), (),
        ("src/verifier/domains/numerical.py",),
    ),
    "vstd-tier3-statics-evaluator": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/domains/statics.py",),
    ),
    "vstd-hardware-ownership-eligibility": (
        "VERIFIER", ("ASSET", "POLICY"), (),
        ("src/verifier/domains/contracts/accountability.py",),
    ),
    "vstd-application-requirements-compiler": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/domains/contracts/application_requirements.py",),
    ),
    "vstd-certificate-dependency-controller": (
        "CONTROLLER", ("ACTUATOR", "MEASUREMENT", "POLICY", "SENSOR", "TRANSACTION"), (),
        ("src/verifier/domains/contracts/certificate_dag.py",),
    ),
    "vstd-consent-certificate-verifier": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "PROTOCOL", "SENSOR"), (),
        ("src/verifier/domains/contracts/consent_checks.py",),
    ),
    "vstd-current-object-replay-router": (
        "CONTROLLER", ("ACTUATOR", "MEASUREMENT", "POLICY", "SENSOR", "TRANSACTION"), (),
        ("src/verifier/domains/contracts/current_object_routes.py",),
    ),
    "vstd-dangerous-pathway-assessor": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/domains/contracts/dangerous_pathway_security.py",),
    ),
    "vstd-facet-obligation-compiler": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/domains/contracts/facet_coverage.py",),
    ),
    "vstd-independence-certificate-verifier": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/domains/contracts/independence_checks.py",),
    ),
    "vstd-independence-projection-policy": (
        "POLICY", ("MEASUREMENT", "SENSOR"), (),
        ("src/verifier/domains/contracts/independence_projection.py",),
    ),
    "vstd-native-child-link-assessor": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/domains/contracts/native_child_links.py",),
    ),
    "vstd-object-address-closure-verifier": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/domains/contracts/object_address_closure.py",),
    ),
    "vstd-object-facet-verifier": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/domains/contracts/object_facets.py",),
    ),
    "vstd-object-governance-protocol": (
        "PROTOCOL", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/domains/contracts/object_governance.py",),
    ),
    "vstd-sim-grounding-verifier": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/domains/contracts/object_grounding.py",),
    ),
    "vstd-object-lineage-verifier": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/domains/contracts/object_lineage.py",),
    ),
    "vstd-object-statics-verifier": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/domains/contracts/object_statics.py",),
    ),
    "vstd-privacy-certificate-verifier": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/domains/contracts/privacy_checks.py",),
    ),
    "vstd-retained-selection-policy": (
        "POLICY", (), (),
        ("src/verifier/domains/contracts/retained_selection.py",),
    ),
    "vstd-reviewed-conflict-refusal-policy": (
        "POLICY", (), (),
        ("src/verifier/domains/contracts/reviewed_conflict_lane_refusals.py",),
    ),
    "vstd-reviewed-singleton-projection-policy": (
        "POLICY", ("MEASUREMENT", "SENSOR"), (),
        (
            "src/verifier/domains/contracts/reviewed_singleton_projections.py",
            "src/verifier/domains/contracts/reviewed_singleton_projections_batch04_06.py",
        ),
    ),
    "vstd-selected-native-context-assessor": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/domains/contracts/selected_native_contexts.py",),
    ),
    "vstd-retained-execution-measurement": (
        "MEASUREMENT", ("POLICY",), (),
        ("src/verifier/domains/contracts/spacetime_execution.py",),
    ),
    "vstd-sim-host-time-mapping-verifier": (
        "VERIFIER", ("MEASUREMENT", "POLICY"), (),
        ("src/verifier/domains/contracts/spacetime_mapping.py",),
    ),
    "vstd-spacetime-capability-measurement": (
        "MEASUREMENT", ("POLICY",), (),
        ("src/verifier/domains/contracts/spacetime_profiles.py",),
    ),
    "vstd-subject-security-chain-verifier": (
        "PROTOCOL", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/domains/contracts/subject_security.py",),
    ),
    "vstd-typed-facet-verifier": (
        "VERIFIER", ("MEASUREMENT", "POLICY", "SENSOR"), (),
        ("src/verifier/domains/contracts/typed_facets.py",),
    ),
    "vstd-typed-facet-projection-policy": (
        "POLICY", ("MEASUREMENT", "SENSOR"), (),
        ("src/verifier/domains/contracts/typed_facets_projection.py",),
    ),
}


EXPECTED_ROOT_ROLE_DECISIONS = {
    "vstd-certificate-dependency-controller": ("VERIFIER", "APPLIES"),
    "vstd-object-governance-protocol": ("VERIFIER", "APPLIES"),
    "vstd-spacetime-capability-measurement": ("VERIFIER", "APPLIES"),
    "vstd-subject-security-chain-verifier": ("VERIFIER", "APPLIES"),
}


def _sha256(lines: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()


def _source_inventory(paths: list[str]) -> list[str]:
    """Capture one complete exact-byte inventory in stable path order."""
    rows = []
    for path in paths:
        content = (ROOT / path).read_bytes()
        rows.append(
            f"{path}\t{len(content)}\t{hashlib.sha256(content).hexdigest()}"
        )
    return rows


def _first(tree: ast.AST, kind: type, predicate=lambda node: True) -> Any:
    """Return the first node of ``kind`` in ast.walk order; fail if absent."""
    for node in ast.walk(tree):
        if isinstance(node, kind) and predicate(node):
            return node
    raise AssertionError(f"no {kind.__name__} target in inventory")


def _body_start(tree: ast.Module) -> int:
    """Index of the first executable statement after an optional module docstring."""
    first = tree.body[0] if tree.body else None
    is_docstring = (
        isinstance(first, ast.Expr)
        and isinstance(first.value, ast.Constant)
        and isinstance(first.value.value, str)
    )
    return 1 if is_docstring else 0


def _mutate_call_name(tree: ast.Module) -> None:
    node = _first(tree, ast.Call, lambda n: isinstance(n.func, ast.Name))
    node.func.id += "_mutant"


def _mutate_attribute_name(tree: ast.Module) -> None:
    node = _first(tree, ast.Attribute)
    node.attr += "_mutant"


def _mutate_int_constant(tree: ast.Module) -> None:
    node = _first(tree, ast.Constant, lambda n: type(n.value) is int)
    node.value += 1


def _mutate_compare_operator(tree: ast.Module) -> None:
    node = _first(tree, ast.Compare)
    node.ops[0] = ast.NotEq() if isinstance(node.ops[0], ast.Eq) else ast.Eq()


def _mutate_binary_operator(tree: ast.Module) -> None:
    node = _first(tree, ast.BinOp)
    node.op = ast.Sub() if isinstance(node.op, ast.Add) else ast.Add()


def _mutate_boolean_operator(tree: ast.Module) -> None:
    node = _first(tree, ast.BoolOp)
    node.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()


def _mutate_if_control_flow(tree: ast.Module) -> None:
    node = _first(tree, ast.If)
    node.test = ast.UnaryOp(op=ast.Not(), operand=node.test)


def _mutate_return_value(tree: ast.Module) -> None:
    node = _first(tree, ast.Return)
    node.value = ast.Constant(value=None if node.value is not None else 0)


def _mutate_added_import(tree: ast.Module) -> None:
    tree.body.insert(
        _body_start(tree),
        ast.Import(names=[ast.alias(name="os", asname=None)]),
    )


def _mutate_import_from_module(tree: ast.Module) -> None:
    node = _first(tree, ast.ImportFrom, lambda n: n.module is not None)
    node.module += "_mutant"


def _mutate_return_annotation(tree: ast.Module) -> None:
    node = _first(tree, ast.FunctionDef)
    node.returns = (
        ast.Name(id="object", ctx=ast.Load()) if node.returns is None else None
    )


def _mutate_argument_annotation(tree: ast.Module) -> None:
    node = _first(tree, ast.FunctionDef, lambda n: bool(n.args.args))
    node.args.args[0].annotation = ast.Name(id="int", ctx=ast.Load())


def _mutate_added_default(tree: ast.Module) -> None:
    node = _first(tree, ast.FunctionDef, lambda n: bool(n.args.args))
    node.args.defaults = [ast.Constant(value=0)]


MUTANTS = (
    _mutate_call_name,
    _mutate_attribute_name,
    _mutate_int_constant,
    _mutate_compare_operator,
    _mutate_binary_operator,
    _mutate_boolean_operator,
    _mutate_if_control_flow,
    _mutate_return_value,
    _mutate_added_import,
    _mutate_import_from_module,
    _mutate_return_annotation,
    _mutate_argument_annotation,
    _mutate_added_default,
)


_PROBE_CODE = (
    "import sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from pathlib import Path\n"
    "from verifier.runtime.package_semantic_ownership_domains import "
    "canonical_executable_ast_sha256\n"
    "source = Path(sys.argv[2]).read_text(encoding='utf-8')\n"
    "print(sys.version.split()[0], canonical_executable_ast_sha256(source))\n"
)


def test_partition_pins_all_semantics_and_exact_residual_paths() -> None:
    actual = {
        item.object_id: (
            item.primary_kind,
            item.specializations,
            item.operands,
            item.owned_paths,
        )
        for item in DOMAIN_OWNERSHIP_SPECS
    }
    assert actual == EXPECTED
    assert len(actual) == 38

    paths = [path for item in DOMAIN_OWNERSHIP_SPECS for path in item.owned_paths]
    assert len(paths) == 39
    assert len(paths) == len(set(paths))
    assert all((ROOT / path).is_file() for path in paths)
    assert all(item.representation_role.strip() for item in DOMAIN_OWNERSHIP_SPECS)
    assert all(item.necessity_reason.strip() for item in DOMAIN_OWNERSHIP_SPECS)
    assert all(item.consequence_boundary.strip() for item in DOMAIN_OWNERSHIP_SPECS)
    assert all(not item.operands for item in DOMAIN_OWNERSHIP_SPECS)


def test_object_inventory_clarification_retains_policy_owner_and_execution() -> None:
    """Pin the only changed owned file independently of the aggregate digest."""
    specs = {item.object_id: item for item in DOMAIN_OWNERSHIP_SPECS}
    owner = specs["vstd-object-obligation-inventory"]
    assert owner.primary_kind == "POLICY"
    assert owner.specializations == ()
    assert owner.operands == ()
    assert owner.owned_paths == (OBJECT_INVENTORY_PATH,)
    assert owner.root_role_decisions == ()

    content = (ROOT / OBJECT_INVENTORY_PATH).read_bytes()
    assert len(content) == OBJECT_INVENTORY_BYTES
    assert hashlib.sha256(content).hexdigest() == OBJECT_INVENTORY_SHA256
    assert canonical_executable_ast_sha256(
        content.decode("utf-8")
    ) == OBJECT_INVENTORY_CANONICAL_EXECUTABLE_AST_SHA256

    document = ast.get_docstring(
        ast.parse(content.decode("utf-8")), clean=False
    )
    assert document is not None
    normalized_document = " ".join(document.split())
    assert (
        "retained 26-``ObjectKind`` by nine-tier native inventory (234 slots)"
        in normalized_document
    )
    assert (
        "12 accumulating consequential roles, for 38 kinds in total"
        in normalized_document
    )
    assert "does not discharge their obligations" in normalized_document
    assert len(ObjectKind) == 26
    registry = namespace_registry()
    assert len(registry) == 38
    assert {
        kind for kind, contract in registry.items() if contract.extends is not None
    } == {
        "LEDGER", "TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR",
        "CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY", "ROBOT", "FINBOT",
    }


def test_partition_does_not_invent_agent_physical_or_market_roles() -> None:
    for item in DOMAIN_OWNERSHIP_SPECS:
        kinds = (item.primary_kind, *item.specializations)
        assert "OBJECT" not in kinds
        assert "BOT" not in kinds
        assert "ROBOT" not in kinds
        assert "FINBOT" not in kinds
        assert "MARKET" not in kinds

    specs = {item.object_id: item for item in DOMAIN_OWNERSHIP_SPECS}
    assert "not a LEDGER" in specs["vstd-object-lineage-verifier"].consequence_boundary
    assert "not a LEDGER" in specs["vstd-subject-security-chain-verifier"].consequence_boundary
    assert "not accelerator arithmetic" in specs["vstd-retained-model-training-arithmetic"].consequence_boundary


def test_partition_pins_four_source_near_accumulated_verifier_roles() -> None:
    actual = {
        item.object_id: (decision.kind, decision.status)
        for item in DOMAIN_OWNERSHIP_SPECS
        for decision in item.root_role_decisions
    }
    assert actual == EXPECTED_ROOT_ROLE_DECISIONS
    for item in DOMAIN_OWNERSHIP_SPECS:
        assert len(item.root_role_decisions) <= 1
        for decision in item.root_role_decisions:
            assert decision.kind != item.primary_kind
            assert decision.status == "APPLIES"
            assert "exact" in decision.reason.lower()
            assert "VERIFIER checking role" in decision.reason


def test_partition_pins_corrected_current_audit_digests() -> None:
    paths = [path for item in DOMAIN_OWNERSHIP_SPECS for path in item.owned_paths]
    assert _sha256(paths) == "a7c4bc242505d683c5ae8a33a0b09d6f54b01cd8e95ca1af467f97d1a5d4fcbe"

    mapping = [
        f"{item.object_id}\t{path}"
        for item in DOMAIN_OWNERSHIP_SPECS
        for path in item.owned_paths
    ]
    assert _sha256(mapping) == "7e3c2838eb00b58a170954c8800662e28bab8de8b0d32f7795cb890d3017375a"

    opening_inventory = _source_inventory(paths)
    closing_inventory = _source_inventory(paths)
    assert opening_inventory == closing_inventory
    assert _sha256(opening_inventory) == "715b6e81154423cd53778b8c026f20cfa15d3d377a3aae316a23ecff65e6d15e"


def test_canonical_form_matches_hand_derived_fixtures() -> None:
    """Expected strings are derived by hand from the field layout, not by running the code."""
    fixtures = {
        "x = 1\n": (
            "Module(body=[Assign(targets=[Name(ctx=Store(),id=str:'x')],"
            "value=Constant(value=int:1))])"
        ),
        '"""module docstring is excluded"""\nx = 1\n': (
            "Module(body=[Assign(targets=[Name(ctx=Store(),id=str:'x')],"
            "value=Constant(value=int:1))])"
        ),
        "def f():\n    pass\n": (
            "Module(body=[FunctionDef(args=arguments(),body=[Pass()],name=str:'f')])"
        ),
        "def f(a=1):\n    pass\n": (
            "Module(body=[FunctionDef(args=arguments(args=[arg(arg=str:'a')],"
            "defaults=[Constant(value=int:1)]),body=[Pass()],name=str:'f')])"
        ),
        "f(1)\n": (
            "Module(body=[Expr(value=Call(args=[Constant(value=int:1)],"
            "func=Name(ctx=Load(),id=str:'f')))])"
        ),
        "x = None\n": (
            "Module(body=[Assign(targets=[Name(ctx=Store(),id=str:'x')],"
            "value=Constant(value=None))])"
        ),
        "1 + 2\n": (
            "Module(body=[Expr(value=BinOp(left=Constant(value=int:1),"
            "op=Add(),right=Constant(value=int:2)))])"
        ),
    }
    for source, expected in fixtures.items():
        assert canonical_executable_ast(ast.parse(source)) == expected, source


def test_canonical_form_distinguishes_value_types_and_operators() -> None:
    digests = {
        canonical_executable_ast_sha256(source)
        for source in ("x = 1\n", "x = 1.0\n", "x = True\n", "x = 'True'\n", "x = 1 + 2\n", "x = 1 - 2\n")
    }
    assert len(digests) == 6


def test_canonical_negative_controls_ignore_comments_and_docstring_text() -> None:
    content = (ROOT / OBJECT_INVENTORY_PATH).read_text(encoding="utf-8")
    base = canonical_executable_ast_sha256(content)
    assert canonical_executable_ast_sha256("# harmless leading comment\n" + content) == base

    tree = ast.parse(content)
    first = tree.body[0]
    assert isinstance(first, ast.Expr)
    lines = content.splitlines(keepends=True)
    relabeled = "".join(
        lines[: first.lineno - 1]
        + ['"""Altered documentation."""\n']
        + lines[first.end_lineno :]
    )
    assert canonical_executable_ast_sha256(relabeled) == base


def test_canonical_mutants_are_each_detected() -> None:
    content = (ROOT / OBJECT_INVENTORY_PATH).read_text(encoding="utf-8")
    tree = ast.parse(content)
    base = canonical_executable_ast_sha256(content)
    survivors = []
    for mutate in MUTANTS:
        mutant = copy.deepcopy(tree)
        mutate(mutant)
        if canonical_executable_ast_sha256_of_tree(mutant) == base:
            survivors.append(mutate.__name__)
    assert survivors == []


def canonical_executable_ast_sha256_of_tree(tree: ast.Module) -> str:
    return hashlib.sha256(canonical_executable_ast(tree).encode("utf-8")).hexdigest()


def test_canonical_digest_agrees_across_probe_interpreters() -> None:
    raw = os.environ.get(PROBE_INTERPRETERS_ENV, "")
    probes = [sys.executable, *[p for p in raw.split(os.pathsep) if p]]
    if len(probes) == 1:
        print(
            f"UNKNOWN cross-interpreter scope: {PROBE_INTERPRETERS_ENV} unset; "
            "only the running interpreter was probed",
            flush=True,
        )
    observed = {}
    for executable in probes:
        completed = subprocess.run(
            [
                executable,
                "-I",
                "-c",
                _PROBE_CODE,
                str(SRC),
                str(ROOT / OBJECT_INVENTORY_PATH),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        version, digest = completed.stdout.split()
        print(f"probe {version} {digest} {executable}", flush=True)
        observed[executable] = digest
    assert set(observed.values()) == {OBJECT_INVENTORY_CANONICAL_EXECUTABLE_AST_SHA256}
