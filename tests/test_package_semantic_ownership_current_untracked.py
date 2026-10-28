"""Exact census, golden role table, mechanism refutations and drift checks for the current untracked batch.

Terminology: abstract syntax tree (AST).

The golden table is a hand-written regression contract, not independent evidence that a
role is correct. Each recorded decision is also anchored to a token that must occur in its
owned source, so a decision cannot cite text the file does not contain. The audit function
below is the refutation mechanism: promotions to ACTUATOR without a physical binding, PROTOCOL,
POLICY or HARNESS without a matching mechanism, state-changing git subprocesses, OBJECT
fallback, and contradicted non-applicability are reported as findings. Mutation cases apply
that audit to altered copies of real rows and to altered source text, so the refusal is
observed rather than assumed.

Token presence is necessary, not sufficient. The launch tokens are a bounded text scan, not an
execution proof, and a mention in a comment counts toward the audit. Verdict and git checks run
over the parsed syntax tree, so prose in a docstring does not establish a verdict or a git call.
That is the conservative direction for these refutations.
"""

from __future__ import annotations

import ast
from collections import Counter
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from verifier.runtime import package_semantic_ownership as central
from verifier.runtime.namespace_contracts import namespace_registry
from verifier.runtime.package_semantic_ownership_current_untracked import (
    AUDITED_SOURCE_DIGESTS,
    CURRENT_UNTRACKED_OWNERSHIP_SPECS,
    INTEGRATION_BLOCKERS,
)
from verifier.runtime.package_semantic_ownership_model import (
    RootRoleDecision,
    SemanticOwnershipSpec,
    root_role_decision,
)


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "src/verifier/runtime/package_semantic_ownership_current_untracked.py"

PATHS = (
    "extensions/languages/src/vstd_languages/extended_batch_two.py",
    "extensions/languages/src/vstd_languages/extended_batch_three.py",
    "src/verifier/core/owned_process.py",
    "src/verifier/domains/contracts/agency_surface.py",
    "src/verifier/runtime/namespace_refutation.py",
    "src/verifier/runtime/package_checker_worker.py",
    "src/verifier/runtime/policy_enforcement_execution.py",
    "src/verifier/runtime/policy_enforcement_routes.py",
    "src/verifier/runtime/policy_enforcement_worker.py",
    "src/verifier/runtime/transaction_execution.py",
)

BATCH_TWO = "vstd-language-extended-batch-two-adapters"
BATCH_THREE = "vstd-language-extended-batch-three-adapters"
OWNED_PROCESS = "vstd-core-owned-process-tree"
AGENCY = "vstd-agency-surface-crosswalk"
NAMESPACE = "vstd-namespace-refutation-witness"
POLICY_EXECUTION = "vstd-policy-enforcement-execution"
POLICY_ROUTES = "vstd-policy-enforcement-routes"
POLICY_WORKER = "vstd-policy-enforcement-worker"
TRANSACTION = "vstd-transaction-execution-coordinator"

# object_id: (path, primary kind, specializations, {retained root: (status, evidence token)}).
# A root absent from the mapping is UNKNOWN, unless it is the primary kind itself.
GOLDEN = {
    BATCH_TWO: (
        PATHS[0], "HARNESS", ("POLICY", "PROTOCOL"),
        {"AGENT": ("DOES_NOT_APPLY", "command(")},
    ),
    BATCH_THREE: (
        PATHS[1], "HARNESS", ("POLICY", "PROTOCOL"),
        {"AGENT": ("DOES_NOT_APPLY", "command(")},
    ),
    OWNED_PROCESS: (
        PATHS[2], "HARNESS", (),
        {"AGENT": ("DOES_NOT_APPLY", "run_owned_process("),
         "VERIFIER": ("DOES_NOT_APPLY", "CLEANUP_CONFIRMED")},
    ),
    AGENCY: (
        PATHS[3], "POLICY", (),
        {"AGENT": ("DOES_NOT_APPLY", "_actual_ids("),
         "BOT": ("DOES_NOT_APPLY", "_replay_child("),
         "HARNESS": ("DOES_NOT_APPLY", "_replay_child("),
         "VERIFIER": ("APPLIES", "recheck_agency_surface_certificate")},
    ),
    NAMESPACE: (
        PATHS[4], "POLICY", (),
        {"AGENT": ("DOES_NOT_APPLY", "_scan_boundary_references"),
         "HARNESS": ("DOES_NOT_APPLY", "a registered closure is a fixed scan of anchored text"),
         "VERIFIER": ("APPLIES", "run_closure")},
    ),
    "vstd-package-checker-worker": (
        PATHS[5], "HARNESS", ("PROTOCOL",),
        {"AGENT": ("DOES_NOT_APPLY", "_load_held_checker("),
         "VERIFIER": ("APPLIES", "PACKAGE_EXECUTION_OBSERVATION_REFUTED")},
    ),
    POLICY_EXECUTION: (
        PATHS[6], "POLICY", (),
        {"AGENT": ("DOES_NOT_APPLY", "issue_authorization("),
         "HARNESS": ("APPLIES", "def _execute("),
         "VERIFIER": ("APPLIES", "auxiliary_evaluate(")},
    ),
    POLICY_ROUTES: (
        PATHS[7], "HARNESS", ("PROTOCOL",),
        {"AGENT": ("DOES_NOT_APPLY", "_CASES"),
         "VERIFIER": ("APPLIES", "evaluate_routes(")},
    ),
    POLICY_WORKER: (
        PATHS[8], "HARNESS", ("PROTOCOL",),
        {"AGENT": ("DOES_NOT_APPLY", "source_pins("),
         "VERIFIER": ("APPLIES", "check_all(")},
    ),
    TRANSACTION: (
        PATHS[9], "TRANSACTION", ("POLICY", "PROTOCOL"),
        {"AGENT": ("DOES_NOT_APPLY", "_authorize("),
         "HARNESS": ("APPLIES", "def observe()"),
         "VERIFIER": ("APPLIES", "_receipt(")},
    ),
}

# One phrase per owned file that must occur in its current bytes.
MARKERS = {
    PATHS[0]: "Reachable through the package, not the host command-line interface",
    PATHS[1]: "Classic Visual Basic (VB6) is fail-closed",
    PATHS[2]: "filesystem, network, syscall, or hostile-host isolation.",
    PATHS[3]: "A passing crosswalk establishes a bounded relation among retained records.",
    PATHS[4]: "a registered closure is a fixed scan of anchored text",
    PATHS[5]: "Compile the held source bytes without consulting a bytecode cache",
    PATHS[6]: "Revision 1 of this mechanism is",
    PATHS[7]: "Fault injection patches only",
    PATHS[8]: "Isolated worker and independent oracle",
    PATHS[9]: "NOT_ESTABLISHED: real authorizer identity",
}

# Process launch or control of any kind. Launch is HARNESS, never ACTUATOR by itself.
LAUNCH_TOKENS = ("subprocess.Popen(", "subprocess.run(", "CreateProcess", "TerminateJobObject",
                 "killpg(", "taskkill")
# Physical command-to-effect binding. An ACTUATOR promotion needs one of these in the source.
ACTUATOR_TOKENS = ("PHYSICAL_ENDPOINT", "REAL_PHYSICAL_BINDING")
EXECUTION_ANCHORS = ("subprocess.Popen(", "exec(code", "def run_owned_process(",
                     "subprocess.run([sys.executable", "routes.observe_all()", "def observe()",
                     "def _execute(")
PROTOCOL_TOKENS = ("SCHEMA", "schema_version", "PROTOCOL", "nonce")
POLICY_GATE_TOKENS = ("RUNNER_ENVIRONMENT_UNSUPPORTED", "RUNNER_CONTRACT_REJECTED",
                      "AUTHORIZATION_TAG_REFUSED", "AUTHORIZATION_REVISION_MISMATCH")
POLICY_PRIMARY_ANCHORS = ("def _evaluate(", "_CLOSURES", "def enforce(")
BATCH_SPECIALIZATIONS = frozenset({"ACTUATOR", "POLICY", "PROTOCOL", "TRANSACTION"})
VERDICT_NAMES = frozenset({"PASS", "FAIL"})
# Git subcommands that only read repository state. Any other subcommand is a state change or unresolved.
READ_ONLY_GIT = frozenset({"status", "log", "diff", "show", "rev-parse", "ls-files", "ls-tree", "cat-file", "describe"})
GIT_OPTIONS_WITH_VALUE = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace"})
LAUNCH_OBSERVATION_PHRASE = "read-only git status"

PHYSICAL_COMMAND_TEXT = '''"""Physical command endpoint for one bench motor."""

PHYSICAL_ENDPOINT = "bench-motor-1"


def send_command(command):
    """Write one command to the physical endpoint and return the observed effect."""
    return {"endpoint": PHYSICAL_ENDPOINT, "command": command, "effect": "observed"}
'''


def _digest(text: bytes) -> str:
    return "sha256:" + hashlib.sha256(text).hexdigest()


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _verdict_references(tree: ast.AST) -> bool:
    """True when code, not prose, names a PASS or FAIL verdict as a string, name or attribute."""
    prose = {
        id(node.value) for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in VERDICT_NAMES \
                and id(node) not in prose:
            return True
        if isinstance(node, ast.Name) and node.id in VERDICT_NAMES:
            return True
        if isinstance(node, ast.Attribute) and node.attr in VERDICT_NAMES:
            return True
    return False


def _git_subcommands(text: str) -> tuple[str, ...]:
    """Git subcommands of every literal argv list that starts with "git", found by syntax, not spelling."""
    found: list[str] = []
    for node in ast.walk(ast.parse(text)):
        if not (isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.List)):
            continue
        items = [
            item.value if isinstance(item, ast.Constant) and isinstance(item.value, str) else None
            for item in node.args[0].elts
        ]
        if not items or items[0] != "git":
            continue
        remaining = iter(items[1:])
        for item in remaining:
            if item is None:
                found.append("UNRESOLVED")
                break
            if item in GIT_OPTIONS_WITH_VALUE:
                next(remaining, None)
                continue
            if item.startswith("-"):
                continue
            found.append(item)
            break
    return tuple(found)


def _returns_bool(text: str, name: str) -> bool:
    return any(
        isinstance(node, ast.FunctionDef) and node.name == name
        and isinstance(node.returns, ast.Name) and node.returns.id == "bool"
        for node in ast.parse(text).body
    )


def actuator_candidate(spec: SemanticOwnershipSpec, text: str) -> bool:
    """An ACTUATOR claim with a physical binding in its source. A candidate is not an admitted actuator."""
    return "ACTUATOR" in spec.specializations and any(token in text for token in ACTUATOR_TOKENS)


def mechanism_findings(spec: SemanticOwnershipSpec, text: str) -> list[str]:
    """Return refutations of one row against the text of its owned source; an empty list is no finding."""
    findings: list[str] = []
    roles = set(spec.specializations)
    decisions = {decision.kind: decision for decision in spec.root_role_decisions}
    primary = spec.primary_kind
    tree = ast.parse(text)
    if primary == "OBJECT":
        findings.append("OBJECT_FALLBACK")
    if roles - BATCH_SPECIALIZATIONS:
        findings.append("CONSEQUENCE_SPECIALIZATION_NOT_EVIDENCED")
    if "ACTUATOR" in roles and not any(token in text for token in ACTUATOR_TOKENS):
        findings.append("ACTUATOR_WITHOUT_PHYSICAL_BINDING")
    if "PROTOCOL" in roles and not any(token in text for token in PROTOCOL_TOKENS):
        findings.append("PROTOCOL_WITHOUT_SCHEMA")
    if "POLICY" in roles and not any(token in text for token in POLICY_GATE_TOKENS):
        findings.append("POLICY_WITHOUT_GATE")
    if primary == "POLICY" and not any(token in text for token in POLICY_PRIMARY_ANCHORS):
        findings.append("POLICY_PRIMARY_WITHOUT_ANCHOR")
    if primary == "HARNESS" and not any(token in text for token in EXECUTION_ANCHORS):
        findings.append("HARNESS_WITHOUT_EXECUTION")
    launches = any(token in text for token in LAUNCH_TOKENS)
    harness = decisions.get("HARNESS")
    harness_classified = primary == "HARNESS" or (harness is not None and harness.status == "APPLIES")
    if launches and not harness_classified:
        findings.append("LAUNCH_NOT_CLASSIFIED")
    if harness is not None and harness.status == "DOES_NOT_APPLY" and (
            launches or any(token in text for token in EXECUTION_ANCHORS)):
        findings.append("HARNESS_DNE_CONTRADICTED")
    if harness is not None and harness.status == "APPLIES" and not any(
            token in text for token in EXECUTION_ANCHORS):
        findings.append("HARNESS_APPLIES_WITHOUT_EXECUTION")
    if any(sub not in READ_ONLY_GIT for sub in _git_subcommands(text)):
        findings.append("GIT_NOT_READ_ONLY")
    verifier = decisions.get("VERIFIER")
    if verifier is not None and verifier.status == "APPLIES" and not _verdict_references(tree):
        findings.append("VERIFIER_WITHOUT_VERDICT")
    if verifier is not None and verifier.status == "DOES_NOT_APPLY" and _verdict_references(tree):
        findings.append("VERIFIER_DNE_CONTRADICTED")
    return findings


def _spec(object_id: str) -> SemanticOwnershipSpec:
    matches = [spec for spec in CURRENT_UNTRACKED_OWNERSHIP_SPECS if spec.object_id == object_id]
    assert len(matches) == 1, object_id
    return matches[0]


def _decision(object_id: str, kind: str) -> RootRoleDecision:
    matches = [item for item in _spec(object_id).root_role_decisions if item.kind == kind]
    assert len(matches) == 1, (object_id, kind)
    return matches[0]


def _root_status(spec: SemanticOwnershipSpec, kind: str) -> str:
    if kind == spec.primary_kind:
        return "PRIMARY"
    for decision in spec.root_role_decisions:
        if decision.kind == kind:
            return decision.status
    return "UNKNOWN"


# --- Census -------------------------------------------------------------------------------------

def test_census_lists_exactly_the_ten_current_untracked_paths() -> None:
    owned = sorted(path for spec in CURRENT_UNTRACKED_OWNERSHIP_SPECS for path in spec.owned_paths)
    assert owned == sorted(PATHS)
    assert len(owned) == 10
    assert set(AUDITED_SOURCE_DIGESTS) == set(PATHS)


def test_pinned_digests_match_current_bytes() -> None:
    for path in PATHS:
        assert AUDITED_SOURCE_DIGESTS[path] == _digest((ROOT / path).read_bytes()), path


def test_census_paths_are_existing_regular_files() -> None:
    for path in PATHS:
        assert (ROOT / path).is_file(), path


def test_rows_are_path_disjoint_and_own_one_path_each() -> None:
    seen: dict[str, str] = {}
    for spec in CURRENT_UNTRACKED_OWNERSHIP_SPECS:
        assert len(spec.owned_paths) == 1, spec.object_id
        for path in spec.owned_paths:
            assert path not in seen, (path, seen.get(path), spec.object_id)
            seen[path] = spec.object_id


def test_census_paths_are_not_yet_owned_by_the_central_catalog() -> None:
    # Documents the current census: the aggregate catalog is not edited by this batch.
    central_owned = {path for spec in central.SEMANTIC_OWNERSHIP_SPECS for path in spec.owned_paths}
    assert central_owned.isdisjoint(PATHS)


def test_exports_a_standalone_tuple_of_ownership_specs() -> None:
    assert type(CURRENT_UNTRACKED_OWNERSHIP_SPECS) is tuple
    assert all(type(spec) is SemanticOwnershipSpec for spec in CURRENT_UNTRACKED_OWNERSHIP_SPECS)
    assert {spec.object_id for spec in CURRENT_UNTRACKED_OWNERSHIP_SPECS} == set(GOLDEN)


def test_module_imports_only_standard_library_and_its_model() -> None:
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert imported <= {
        "__future__", "dataclasses", "typing", "verifier.runtime.package_semantic_ownership_model",
    }
    assert "verifier.runtime.package_semantic_ownership" not in imported


def test_central_validator_accepts_the_standalone_rows() -> None:
    validated = central.validate_catalog(
        ROOT, CURRENT_UNTRACKED_OWNERSHIP_SPECS, registry=namespace_registry())
    assert len(validated) == 10


# --- Golden roles and anchored evidence ----------------------------------------------------------

@pytest.mark.parametrize("object_id", sorted(GOLDEN))
def test_primary_and_specializations_match_golden(object_id: str) -> None:
    primary, specializations = GOLDEN[object_id][1], GOLDEN[object_id][2]
    spec = _spec(object_id)
    assert spec.primary_kind == primary
    assert spec.specializations == tuple(sorted(specializations))
    assert spec.primary_kind != "OBJECT"


@pytest.mark.parametrize("object_id", sorted(GOLDEN))
def test_retained_roots_match_golden_and_missing_decisions_stay_unknown(object_id: str) -> None:
    decisions = GOLDEN[object_id][3]
    spec = _spec(object_id)
    registry = namespace_registry()
    for kind in sorted(name for name, entry in registry.items() if entry.extends is None):
        expected = decisions[kind][0] if kind in decisions else "UNKNOWN"
        if kind == spec.primary_kind:
            expected = "PRIMARY"
        assert _root_status(spec, kind) == expected, (object_id, kind)


@pytest.mark.parametrize("object_id", sorted(GOLDEN))
def test_every_decision_reason_cites_a_token_present_in_its_source(object_id: str) -> None:
    decisions = GOLDEN[object_id][3]
    text = _text(GOLDEN[object_id][0])
    for kind, (status, token) in decisions.items():
        decision = _decision(object_id, kind)
        assert decision.status == status
        assert token in decision.reason, (object_id, kind)
        assert token in text, (object_id, kind, token)


@pytest.mark.parametrize("path", PATHS)
def test_source_markers_are_present_in_current_bytes(path: str) -> None:
    assert MARKERS[path] in _text(path), path


@pytest.mark.parametrize("object_id", sorted(GOLDEN))
def test_current_rows_have_no_mechanism_findings(object_id: str) -> None:
    assert mechanism_findings(_spec(object_id), _text(GOLDEN[object_id][0])) == []


def test_object_is_never_a_primary_or_retained_root() -> None:
    for spec in CURRENT_UNTRACKED_OWNERSHIP_SPECS:
        assert spec.primary_kind != "OBJECT"
        assert "OBJECT" not in spec.specializations
        assert all(decision.kind != "OBJECT" for decision in spec.root_role_decisions)


def test_no_operand_targets_are_invented_and_blockers_are_explicit() -> None:
    assert all(spec.operands == () for spec in CURRENT_UNTRACKED_OWNERSHIP_SPECS)
    assert type(INTEGRATION_BLOCKERS) is tuple and INTEGRATION_BLOCKERS
    assert any("aggregate" in blocker for blocker in INTEGRATION_BLOCKERS)


def test_every_row_records_consequence_boundary_and_necessity() -> None:
    for spec in CURRENT_UNTRACKED_OWNERSHIP_SPECS:
        assert spec.necessity_reason.strip() and spec.consequence_boundary.strip()
        assert spec.representation_role.strip()


def test_read_only_git_launch_is_declared_as_harness_observation() -> None:
    spec = _spec(POLICY_EXECUTION)
    assert LAUNCH_OBSERVATION_PHRASE in _decision(POLICY_EXECUTION, "HARNESS").reason
    assert "ACTUATOR" not in spec.specializations
    assert mechanism_findings(spec, _text(PATHS[6])) == []


# --- Launch is HARNESS; ACTUATOR needs a physical binding ----------------------------------------

def test_actuator_tokens_are_physical_bindings_not_process_launch() -> None:
    assert set(ACTUATOR_TOKENS).isdisjoint(LAUNCH_TOKENS)
    assert not any("subprocess" in token or "taskkill" in token for token in ACTUATOR_TOKENS)


def test_no_current_row_promotes_process_control_to_actuator() -> None:
    for spec in CURRENT_UNTRACKED_OWNERSHIP_SPECS:
        assert "ACTUATOR" not in spec.specializations, spec.object_id
        assert "ACTUATOR_WITHOUT_PHYSICAL_BINDING" not in mechanism_findings(spec, _text(spec.owned_paths[0]))


def test_process_only_launch_is_harness_and_refused_as_actuator() -> None:
    spec = _spec(OWNED_PROCESS)
    text = _text(PATHS[2])
    findings = mechanism_findings(spec, text)
    assert "LAUNCH_NOT_CLASSIFIED" not in findings
    assert not any(finding.startswith("ACTUATOR") for finding in findings)
    promoted = replace(spec, specializations=("ACTUATOR",))
    assert "ACTUATOR_WITHOUT_PHYSICAL_BINDING" in mechanism_findings(promoted, text)
    assert not actuator_candidate(promoted, text)


def test_physical_command_to_effect_is_an_actuator_candidate() -> None:
    spec = replace(_spec(OWNED_PROCESS), specializations=("ACTUATOR",))
    assert "ACTUATOR_WITHOUT_PHYSICAL_BINDING" not in mechanism_findings(spec, PHYSICAL_COMMAND_TEXT)
    assert actuator_candidate(spec, PHYSICAL_COMMAND_TEXT)


def test_real_physical_classification_label_alone_is_not_an_actuator_binding() -> None:
    spec = replace(_spec(AGENCY), specializations=("ACTUATOR",))
    assert "REAL_PHYSICAL" in _text(PATHS[3])
    assert "ACTUATOR_WITHOUT_PHYSICAL_BINDING" in mechanism_findings(spec, _text(PATHS[3]))


def test_launch_in_a_row_without_harness_classification_is_refused() -> None:
    spec = _spec(NAMESPACE)
    launched = _text(PATHS[4]) + "\nsubprocess.run(['verify'])\n"
    assert "LAUNCH_NOT_CLASSIFIED" in mechanism_findings(spec, launched)


def test_language_adapter_without_launch_code_is_not_harness() -> None:
    spec = _spec(BATCH_TWO)
    text = _text(PATHS[0])
    stripped = text.replace("subprocess.Popen(", "popen_absent(").replace("subprocess.run(", "run_absent(")
    assert "HARNESS_WITHOUT_EXECUTION" in mechanism_findings(spec, stripped)


def test_batch_three_adapter_without_launch_code_is_refused() -> None:
    spec = _spec(BATCH_THREE)
    stripped = _text(PATHS[1]).replace("subprocess.Popen(", "popen_absent(")
    assert "HARNESS_WITHOUT_EXECUTION" in mechanism_findings(spec, stripped)


# --- Git observation: read-only versus state-changing, by subcommand ----------------------------

def test_read_only_git_observation_is_not_a_state_change() -> None:
    spec = _spec(POLICY_EXECUTION)
    text = _text(PATHS[6])
    assert _git_subcommands(text) == ("status",)
    assert "GIT_NOT_READ_ONLY" not in mechanism_findings(spec, text)


def test_state_changing_git_subprocess_is_refused_by_subcommand_not_spelling() -> None:
    spec = _spec(POLICY_EXECUTION)
    text = _text(PATHS[6])
    reset = text.replace('"status", "--porcelain"', '"reset", "--hard"')
    assert _git_subcommands(reset) == ("reset",)
    assert "GIT_NOT_READ_ONLY" in mechanism_findings(spec, reset)
    # Same effect spelled with a -C option that carries a value; the subcommand is still checkout.
    spelled = text.replace('"--no-optional-locks", "status", "--porcelain"', '"-C", ".", "checkout", "--"')
    assert _git_subcommands(spelled) == ("checkout",)
    assert "GIT_NOT_READ_ONLY" in mechanism_findings(spec, spelled)
    appended = text + "\nsubprocess.run(['git', 'commit', '-m', 'x'])\n"
    assert "GIT_NOT_READ_ONLY" in mechanism_findings(spec, appended)


def test_read_only_git_observation_is_not_actuation_even_when_promoted() -> None:
    spec = replace(_spec(POLICY_EXECUTION), specializations=("ACTUATOR",))
    assert "ACTUATOR_WITHOUT_PHYSICAL_BINDING" in mechanism_findings(spec, _text(PATHS[6]))


# --- Reason framing: composition, not absence of decision ---------------------------------------

@pytest.mark.parametrize("object_id", [AGENCY, NAMESPACE, POLICY_EXECUTION, OWNED_PROCESS, BATCH_TWO, BATCH_THREE])
def test_agent_reason_names_missing_composition_not_an_absent_decision(object_id: str) -> None:
    reason = _decision(object_id, "AGENT").reason
    assert "S + decider + HARNESS composition" in reason
    assert "no decision" not in reason and "no agent identity" not in reason


def test_adapter_runner_reason_acknowledges_compiler_execution() -> None:
    assert "compiler" in _spec(BATCH_TWO).necessity_reason
    assert "compiler" in _decision(BATCH_TWO, "AGENT").reason
    assert "dotnet build" in _spec(BATCH_THREE).necessity_reason


def test_owned_process_is_harness_over_lifetime_and_not_a_guaranteed_tree() -> None:
    spec = _spec(OWNED_PROCESS)
    assert spec.primary_kind == "HARNESS" and spec.specializations == ()
    text = " ".join([spec.necessity_reason, spec.consequence_boundary])
    assert "process group" in text and "setsid" in text
    assert "guaranteed tree" in text
    assert "entire" not in text


def test_policy_worker_independence_is_module_level_and_parent_side() -> None:
    reason = _spec(POLICY_WORKER).necessity_reason
    assert "module-level" in reason and "parent-side" in reason
    module = ast.parse(_text(PATHS[8]))
    imported = {alias.name for node in module.body if isinstance(node, ast.Import) for alias in node.names}
    imported |= {node.module or "" for node in module.body if isinstance(node, ast.ImportFrom)}
    assert not any("policy_enforcement_routes" in name or "policy_enforcement_execution" in name for name in imported)
    routes = ast.parse(_text(PATHS[7]))
    evaluate = next(node for node in routes.body if isinstance(node, ast.FunctionDef) and node.name == "evaluate_routes")
    calls = {ast.unparse(node.func) for node in ast.walk(evaluate) if isinstance(node, ast.Call)}
    assert "oracle.check_all" in calls


def test_transaction_verifier_cites_receipt_emission_not_the_bool_oracle() -> None:
    reason = _decision(TRANSACTION, "VERIFIER").reason
    assert "_receipt(" in reason and "PASS" in reason and "FAIL" in reason
    assert _returns_bool(_text(PATHS[9]), "check_observations")


# --- Verdict authority: code, not prose --------------------------------------------------------

def test_adapter_prose_pass_does_not_establish_verifier_applicability() -> None:
    spec = _spec(BATCH_TWO)
    promoted = replace(spec, root_role_decisions=(
        root_role_decision("VERIFIER", "APPLIES", "candidate verdict described in the docstring"),
    ))
    assert "VERIFIER_WITHOUT_VERDICT" in mechanism_findings(promoted, _text(PATHS[0]))


def test_verifier_non_applicability_is_contradicted_by_a_verdict_literal() -> None:
    spec = _spec(OWNED_PROCESS)
    with_verdict = _text(PATHS[2]) + '\nRESULT = "PASS"\n'
    assert "VERIFIER_DNE_CONTRADICTED" in mechanism_findings(spec, with_verdict)


def test_adapter_verifier_is_unknown_with_a_typed_exit_code_basis() -> None:
    from verifier.runtime.package_semantic_ownership_current_untracked import applicability_records

    for object_id in (BATCH_TWO, BATCH_THREE):
        record = next(item for item in applicability_records(_spec(object_id)) if item.kind == "VERIFIER")
        assert record.status == "UNKNOWN"
        assert "exit code" in record.basis
        assert _root_status(_spec(object_id), "VERIFIER") == "UNKNOWN"


def test_agency_surface_verifies_labels_without_instantiating_them() -> None:
    spec = _spec(AGENCY)
    for kind in ("AGENT", "BOT", "ROBOT", "FINBOT"):
        assert _root_status(spec, kind) != "APPLIES", kind
    assert _root_status(spec, "BOT") == "DOES_NOT_APPLY"
    assert not {"AGENT", "BOT", "ROBOT", "FINBOT"} & set(spec.specializations)


def test_agency_surface_cannot_take_robot_or_finbot_consequence_roles() -> None:
    spec = _spec(AGENCY)
    promoted = replace(spec, specializations=("FINBOT", "ROBOT"))
    assert "CONSEQUENCE_SPECIALIZATION_NOT_EVIDENCED" in mechanism_findings(promoted, _text(PATHS[3]))


def test_agency_surface_harness_non_applicability_is_refuted_by_a_launch() -> None:
    spec = _spec(AGENCY)
    launched = _text(PATHS[3]) + "\nsubprocess.run(['verify'])\n"
    assert "HARNESS_DNE_CONTRADICTED" in mechanism_findings(spec, launched)


def test_namespace_refutation_cannot_be_promoted_to_harness_primary() -> None:
    spec = _spec(NAMESPACE)
    promoted = replace(spec, primary_kind="HARNESS")
    findings = mechanism_findings(promoted, _text(PATHS[4]))
    assert "HARNESS_WITHOUT_EXECUTION" in findings


def test_owned_process_protocol_claim_is_refused_without_a_schema() -> None:
    spec = _spec(OWNED_PROCESS)
    promoted = replace(spec, specializations=("PROTOCOL",))
    assert "PROTOCOL_WITHOUT_SCHEMA" in mechanism_findings(promoted, _text(PATHS[2]))


def test_object_fallback_is_refused_for_every_row() -> None:
    for spec in CURRENT_UNTRACKED_OWNERSHIP_SPECS:
        fallback = replace(spec, primary_kind="OBJECT")
        assert "OBJECT_FALLBACK" in mechanism_findings(fallback, _text(spec.owned_paths[0]))


def test_policy_worker_without_case_execution_is_not_harness() -> None:
    spec = _spec(POLICY_WORKER)
    stripped = _text(PATHS[8]).replace("routes.observe_all()", "routes_absent()")
    assert "HARNESS_WITHOUT_EXECUTION" in mechanism_findings(spec, stripped)


def test_checker_worker_substitution_without_held_execution_is_refused() -> None:
    spec = _spec("vstd-package-checker-worker")
    substituted = _text(PATHS[5]).replace("exec(code, module.__dict__)", "pass")
    assert "HARNESS_WITHOUT_EXECUTION" in mechanism_findings(spec, substituted)


def test_transaction_harness_applicability_is_refused_without_its_observation_driver() -> None:
    spec = _spec(TRANSACTION)
    stripped = _text(PATHS[9]).replace("def observe()", "def observe_removed()")
    assert "HARNESS_APPLIES_WITHOUT_EXECUTION" in mechanism_findings(spec, stripped)


def test_central_validator_refuses_a_refined_kind_as_retained_root() -> None:
    spec = _spec(AGENCY)
    refined_root = replace(spec, root_role_decisions=(
        RootRoleDecision("POLICY", "APPLIES", "mislabelled refined root"),
    ))
    with pytest.raises(ValueError, match="PACKAGE_SEMANTIC_OWNERSHIP_ROOT_ROLE_INVALID"):
        central.validate_catalog(ROOT, (refined_root,), registry=namespace_registry())


def test_central_validator_refuses_invented_operand_targets() -> None:
    spec = _spec(AGENCY)
    invented = replace(spec, operands=(("objects", ("vstd-invented-target",)),))
    with pytest.raises(ValueError, match="TYPED_LAYOUT_INVALID"):
        central.validate_catalog(ROOT, (invented,), registry=namespace_registry())


# --- Applicability coverage over the 38 registered kinds ---------------------------------------

def test_coverage_names_every_registered_kind_once_per_row() -> None:
    from verifier.runtime.package_semantic_ownership_current_untracked import REGISTERED_KINDS, applicability_records

    assert len(REGISTERED_KINDS) == 38 == len(set(REGISTERED_KINDS))
    assert set(REGISTERED_KINDS) == set(namespace_registry())
    for spec in CURRENT_UNTRACKED_OWNERSHIP_SPECS:
        records = applicability_records(spec)
        assert [record.kind for record in records] == sorted(REGISTERED_KINDS), spec.object_id
        assert all(type(record).__name__ == "ApplicabilityRecord" for record in records)


def test_refined_kind_split_matches_the_registry() -> None:
    from verifier.runtime.package_semantic_ownership_current_untracked import REFINED_KINDS

    registry = namespace_registry()
    assert REFINED_KINDS == frozenset(name for name, entry in registry.items() if entry.extends is not None)


def test_unknown_denominator_is_explicit_and_never_an_exemption() -> None:
    from verifier.runtime.package_semantic_ownership_current_untracked import applicability_records

    for spec in CURRENT_UNTRACKED_OWNERSHIP_SPECS:
        records = applicability_records(spec)
        counts = Counter(record.status for record in records)
        decided = 1 + len(spec.specializations) + len(spec.root_role_decisions)
        assert counts["PRIMARY"] == 1
        assert counts["SPECIALIZATION"] == len(spec.specializations), spec.object_id
        assert counts["APPLIES"] + counts["DOES_NOT_APPLY"] == len(spec.root_role_decisions), spec.object_id
        assert counts["UNKNOWN"] == 38 - decided, spec.object_id
        assert all(record.basis for record in records if record.status == "UNKNOWN")


def test_refined_kinds_are_specializations_only_when_claimed() -> None:
    from verifier.runtime.package_semantic_ownership_current_untracked import REFINED_KINDS, applicability_records

    for spec in CURRENT_UNTRACKED_OWNERSHIP_SPECS:
        for record in applicability_records(spec):
            if record.kind in REFINED_KINDS:
                if record.kind == spec.primary_kind:
                    expected = "PRIMARY"
                elif record.kind in spec.specializations:
                    expected = "SPECIALIZATION"
                else:
                    expected = "UNKNOWN"
                assert record.status == expected, (spec.object_id, record.kind)


def test_object_is_recorded_as_unknown_forbidden_fallback_for_every_row() -> None:
    from verifier.runtime.package_semantic_ownership_current_untracked import applicability_records

    for spec in CURRENT_UNTRACKED_OWNERSHIP_SPECS:
        record = next(item for item in applicability_records(spec) if item.kind == "OBJECT")
        assert record.status == "UNKNOWN"
        assert "FORBIDDEN" in record.basis


# --- Source drift and worker substitution -------------------------------------------------------

def _drift_findings(path: str, observed: bytes) -> list[str]:
    return [] if _digest(observed) == AUDITED_SOURCE_DIGESTS[path] else ["DIGEST_DRIFT:" + path]


def test_drifted_checker_worker_copy_is_reported(tmp_path: Path) -> None:
    copied = tmp_path / "package_checker_worker.py"
    copied.write_bytes((ROOT / PATHS[5]).read_bytes() + b"\n# substituted worker\n")
    assert _drift_findings(PATHS[5], copied.read_bytes()) == ["DIGEST_DRIFT:" + PATHS[5]]


def test_substituted_policy_worker_bytes_change_the_pinned_digest(tmp_path: Path) -> None:
    substituted = tmp_path / "policy_enforcement_worker.py"
    substituted.write_bytes(_text(PATHS[8]).replace("check_all(", "accept_all(").encode("utf-8"))
    assert _digest(substituted.read_bytes()) != AUDITED_SOURCE_DIGESTS[PATHS[8]]


def test_pinned_digest_format_is_sha256_prefixed_hex() -> None:
    for path, digest in AUDITED_SOURCE_DIGESTS.items():
        assert digest.startswith("sha256:") and len(digest) == len("sha256:") + 64, path
