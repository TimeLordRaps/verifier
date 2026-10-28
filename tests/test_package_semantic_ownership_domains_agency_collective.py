"""Exact census, source-mechanism grounding, and mutation oracles for the agency-collective batch.

Terminology: abstract syntax tree (AST).

Secure Hash Algorithm 256-bit (SHA-256) digests pin each owned source file's raw bytes. Digests and
marker substrings are not proof. Each APPLIES, DOES_NOT_APPLY and root decision is accepted only when
an executable predicate over the parsed source finds its decisive condition under its dispatch guard.
Comments, docstrings, string literals and digests are never consulted, so re-pinning them cannot
satisfy a predicate. Each predicate is then checked against source in which its decisive condition is
disabled, and the eight confirmed wrong-reason classes are pinned as named mutant tests.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
from functools import lru_cache
from pathlib import Path
import re
import shutil

import pytest

from verifier.core import namespace
from verifier.runtime import package_semantic_ownership_domains_agency_collective as batch
from verifier.runtime.package_semantic_ownership_model import (
    SemanticOwnershipSpec,
    root_role_decision,
)


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "src/verifier/runtime/package_semantic_ownership_domains_agency_collective.py"
D = "src/verifier/domains/"
C = "src/verifier/domains/contracts/"

EXPECTED_PATHS = (
    D + "actor.py",
    D + "agent.py",
    D + "bench.py",
    D + "bot.py",
    D + "collective.py",
    D + "human.py",
    C + "agent_checks.py",
    C + "agent_ceiling_fixity.py",
    C + "actor_closure.py",
    C + "actor_decision_record.py",
    C + "actor_replay.py",
    C + "arch_resolution.py",
    C + "arch_schedule.py",
    C + "arch_shapes.py",
    C + "bench_attempts.py",
    C + "bench_checks.py",
    C + "bench_checks_projection.py",
    C + "bot_checks.py",
    C + "bot_inherited_ceiling.py",
    C + "collective_closure.py",
    C + "collective_constraints.py",
    C + "collective_lifecycle.py",
    C + "human_no_composition.py",
    C + "human_population_declaration.py",
    C + "human_template_irreversibility.py",
)

# Full-file SHA-256 at the time these rows were audited.  Drift is a failure.
EXPECTED_DIGESTS = {
    D + "actor.py": "cea3c698ed0d62e11ceb4ef478b61f1c42911c09ab7f76072a362abc4d482117",
    D + "agent.py": "0a793d1dc210a7ffb6d143c6ff227dd112fe11f41b5cfdff856037cb588d0f50",
    D + "bench.py": "924a122aa24d34927ee679c24a98fac81e5f4201fa5025fa712dc575f25dc4db",
    D + "bot.py": "4f2e5d0bdc203c60a6efeb37a3e8e8dd2f64cde7ceedfe831855ccedde1e409c",
    D + "collective.py": "9015e91474773797455bc8c52546bc4dd37d7f5ec5ff361ffd9f726b70147ede",
    D + "human.py": "d1fc9d70d65552fe64d37d8e3c86bae71a68ad8f74ac36e1bcc85916cdca0fb3",
    C + "actor_closure.py": "d14f86637a2479fe33ff2edc170b109aead09e27416bd1410d120e0cec61ce21",
    C + "actor_decision_record.py": "f4c19aebfb5a66f2fb88f513a726e753c6ce48a04b6962f0aa37fb91d9ac51bd",
    C + "actor_replay.py": "564d890c5bfb48cd4a5622361d0ea50c874f19af8dc9bc7743f50c22b0f41438",
    C + "agent_ceiling_fixity.py": "7b107e458dd8a947d365089b1aacaef46f2408e61270f9645a289e62c03453cc",
    C + "agent_checks.py": "3dad2c6ec04e3a6dce548c4dfd114684369778300db853876f7f13052e256708",
    C + "bot_checks.py": "3e18c90aa7583243c90585770abd90ab44384352110c4bdf1ef1cb7805408661",
    C + "bot_inherited_ceiling.py": "29477927b30750028f6201cf67948695b74bbf15db2f7ec0f8203c490e27d6e3",
    C + "collective_closure.py": "bb148e92c0c8151d42796ee957ef280061db6e64e16ac681d6f1e668af726673",
    C + "collective_constraints.py": "72d0f38838b65268acf0a539262e5161b18b5209ede7145bbf61f514c8c691b9",
    C + "collective_lifecycle.py": "73085730c3176295ed294bc2345048cb05c518113f95db1fb59b385859ef2495",
    C + "bench_attempts.py": "040defe90c721f33a41e75510bf562dfd564c9f32b62009ed43efd14ece47176",
    C + "bench_checks.py": "3826e27fba32889349b989be5e6362bcc5a04ddce8aa897e1243b31bc13a4e5a",
    C + "bench_checks_projection.py": "6d642695777878a8e437e07bb7e68bf282975f14dd04daeef3a6e67dfa726cb6",
    C + "human_no_composition.py": "22dc7a5a736671c0ae2d3082df9e24864633854c052e811ae8ea85991326a816",
    C + "human_population_declaration.py": "5e1fdde605ca886b670c0744ea7e3e4497750a770bfdff373633fe5579ff4e85",
    C + "human_template_irreversibility.py": "a45f84bf6cf8f02d3937124e57b18ff404df1b9d6fe39b10e2581607a97dab75",
    C + "arch_resolution.py": "fe080259b172572d883d154e094f22fa8c4eddfecebdfe8ab03c62a8702a4c8c",
    C + "arch_schedule.py": "ebf5c39f9f90f525b7a3e40f467324c6f70d27a2d87080f5fd3266202ab1a764",
    C + "arch_shapes.py": "9c47e5d33d7c3934460e268fb52f7150cc30e603cdc4600672db575fe712b391",
}

# Path to (object, primary kind).  Any other owner, missing path, or extra path fails.
EXPECTED_OWNERS = {
    **{path: ("vstd-actor", "ACTOR") for path in (D + "actor.py", C + "actor_closure.py",
                                                    C + "actor_decision_record.py", C + "actor_replay.py")},
    **{path: ("vstd-agent", "AGENT") for path in (D + "agent.py", C + "agent_ceiling_fixity.py",
                                                    C + "agent_checks.py")},
    **{path: ("vstd-bot", "BOT") for path in (D + "bot.py", C + "bot_checks.py",
                                                C + "bot_inherited_ceiling.py")},
    **{path: ("vstd-collective", "COLLECTIVE") for path in (D + "collective.py", C + "collective_closure.py",
                                                              C + "collective_constraints.py",
                                                              C + "collective_lifecycle.py")},
    **{path: ("vstd-benchmark", "BENCH") for path in (D + "bench.py", C + "bench_attempts.py",
                                                        C + "bench_checks.py", C + "bench_checks_projection.py")},
    **{path: ("vstd-human", "HUMAN") for path in (D + "human.py", C + "human_no_composition.py",
                                                    C + "human_population_declaration.py",
                                                    C + "human_template_irreversibility.py")},
    **{path: ("vstd-architecture", "ARCH") for path in (C + "arch_resolution.py", C + "arch_schedule.py",
                                                          C + "arch_shapes.py")},
}

# Outcome pin after the confirmed repair.  It records what the table decides; each decision is
# accepted only by the source-mechanism predicates below, never by this table alone.
EXPECTED_ROLES = {
    "vstd-actor": {"APPLIES": ("POLICY",), "DOES_NOT_APPLY": ()},
    "vstd-agent": {"APPLIES": (), "DOES_NOT_APPLY": ()},
    "vstd-bot": {"APPLIES": (), "DOES_NOT_APPLY": ()},
    "vstd-collective": {"APPLIES": ("LEDGER", "POLICY"), "DOES_NOT_APPLY": ()},
    "vstd-benchmark": {"APPLIES": ("MEASUREMENT",), "DOES_NOT_APPLY": ()},
    "vstd-human": {"APPLIES": (), "DOES_NOT_APPLY": ()},
    "vstd-architecture": {"APPLIES": (), "DOES_NOT_APPLY": ()},
}

# Typed operand slots left unbound, as (object, slot, target kinds).
EXPECTED_BLOCKERS = (
    ("vstd-actor", "representation", ("AGENT", "BOT", "HUMAN")),
    ("vstd-actor", "root_human", ("HUMAN",)),
    ("vstd-agent", "env", ("ENV",)),
    ("vstd-agent", "harness", ("HARNESS",)),
    ("vstd-agent", "model", ("MODEL",)),
    ("vstd-benchmark", "data", ("DATA",)),
    ("vstd-benchmark", "verifier", ("VERIFIER",)),
    ("vstd-bot", "agent", ("AGENT",)),
    ("vstd-bot", "env", ("ENV",)),
    ("vstd-bot", "sim", ("SIM",)),
    ("vstd-collective", "roles", ("ROLE",)),
)

ALLOWED_IMPORTS = {
    "__future__", "ast", "dataclasses", "hashlib", "pathlib", "re", "typing",
    "verifier.runtime.package_semantic_ownership_model",
}

# Name fragments that make a refuting If test an effect, feedback, liveness or consequence check.
EFFECT_TOKENS = ("actuat", "effect", "command")
LIVENESS_TOKENS = ("timeout", "deadline", "liveness", "progress", "failure", "recover", "retry", "stall")
FEEDBACK_TOKENS = ("feedback", "setpoint", "control_signal", "correction", "error_signal")
CONSEQUENCE_TOKENS = {
    "ACTUATOR": EFFECT_TOKENS,
    "CONTROLLER": FEEDBACK_TOKENS,
    "FINBOT": ("amount", "account", "settlement", "payment", "financial", "currency"),
    "ROBOT": ("agent", "harness", "physical", "actuat", "command"),
}


def _validate(specs=None, decisions=None, census=None, digests=None):
    return batch.validate_batch(
        batch.SEMANTIC_OWNERSHIP_SPECS if specs is None else specs,
        batch.SOURCE_ROLE_DECISIONS if decisions is None else decisions,
        batch.PATH_CENSUS if census is None else census,
        batch.SOURCE_DIGESTS if digests is None else digests,
    )


def _owner_map(specs) -> dict[str, tuple[str, str]]:
    return {
        path: (spec.object_id, spec.primary_kind)
        for spec in specs
        for path in spec.owned_paths
    }


def _decision(object_id: str, role: str, status: str = "APPLIES", *, evidence=None, reason=None):
    source = [row for row in batch.SOURCE_ROLE_DECISIONS if row.object_id == object_id and row.role == role]
    base = source[0] if source else None
    return batch.SourceRoleDecision(
        object_id=object_id,
        role=role,
        status=status,
        evidence=evidence if evidence is not None else (base.evidence if base else ()),
        reason=reason if reason is not None else (base.reason if base else "bot.py reason"),
        applicability=base.applicability if base else "UNCONDITIONAL",
        next_action=base.next_action if base else "test-only decision",
        checker=base.checker if base else "test_decision_table_is_golden_and_specializations_follow_applies_only",
    )


def _replace_row(object_id: str, **changes):
    return tuple(
        dataclasses.replace(spec, **changes) if spec.object_id == object_id else spec
        for spec in batch.SEMANTIC_OWNERSHIP_SPECS
    )


def _expect(code: str, fn, *args):
    with pytest.raises(ValueError, match=code):
        fn(*args)


def _status(object_id: str, role: str) -> str | None:
    """APPLIES or DOES_NOT_APPLY for a decided cell; None when no decision row exists."""
    for row in batch.SOURCE_ROLE_DECISIONS:
        if (row.object_id, row.role) == (object_id, role):
            return row.status
    return None


def _unknown_record(object_id: str, role: str):
    return next(
        (record for record in batch.unresolved_records() if (record.object_id, record.role) == (object_id, role)),
        None,
    )


def _assert_retained_not_source(object_id: str, role: str) -> None:
    """Retention keeps the obligation without claiming source mechanism evidence."""
    assert _status(object_id, role) is None
    assert _unknown_record(object_id, role) is None
    assert role in batch.OBLIGATION_RETENTION_APPLIES[object_id]


def _row(object_id: str, role: str):
    return next((r for r in batch.SOURCE_ROLE_DECISIONS if r.object_id == object_id and r.role == role), None)


def _declared_checker(name: str):
    if name == "test_bench_measurement_is_conditional_on_the_budgets_check":
        return test_bench_measurement_is_conditional_on_the_budgets_check
    if name == "test_decision_table_is_golden_and_specializations_follow_applies_only":
        return test_decision_table_is_golden_and_specializations_follow_applies_only
    if name == "test_root_role_decision_must_match_the_decision_table":
        return test_root_role_decision_must_match_the_decision_table
    return None


def _string_constants(path: str, start: int, end: int) -> list[str]:
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"), filename=path)
    return [
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and start <= node.lineno <= end
    ]


def _call_string_args(path: str, start: int, end: int) -> list[str]:
    """Literal string arguments of calls on the cited lines: Refuted message text and same() messages."""
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"), filename=path)
    return [
        arg.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and start <= node.lineno <= end
        for arg in node.args
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
    ]


# ---------------------------------------------------------------------------------------------
# Source-mechanism predicates.  A predicate reads the parsed source only: an executable If test
# or a same(...) replay under its dispatch guard.  Guards are the unparsed tests of enclosing
# branches, with "not (...)" for an else branch.  Literal messages, comments and docstrings are
# never a predicate input.
# ---------------------------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _real_trees() -> dict[str, ast.Module]:
    return {
        path: ast.parse((ROOT / path).read_text(encoding="utf-8"), filename=path)
        for path in batch.PATH_CENSUS
    }


def _visit(node: ast.AST, guards: tuple[str, ...] = ()):
    """Yield (node, guards) for every node, where guards are the enclosing dispatch tests."""
    yield node, guards
    for field, value in ast.iter_fields(node):
        if isinstance(node, (ast.If, ast.IfExp)) and field in ("body", "orelse"):
            test = ast.unparse(node.test)
            guard = test if field == "body" else f"not ({test})"
            for child in (value if isinstance(value, list) else [value]):
                yield from _visit(child, guards + (guard,))
        elif isinstance(value, list):
            for child in value:
                if isinstance(child, ast.AST):
                    yield from _visit(child, guards)
        elif isinstance(value, ast.AST):
            yield from _visit(value, guards)


def _refutes(body: list[ast.stmt]) -> bool:
    return any(
        isinstance(stmt, ast.Raise) and isinstance(stmt.exc, ast.Call)
        and isinstance(stmt.exc.func, ast.Name) and stmt.exc.func.id == "Refuted"
        for stmt in body
    )


def _decisive(trees, path: str, function: str, fragment: str, guard: str | None = None) -> bool:
    """A refuting If whose test contains fragment, or a same(...) replay of fragment, in function."""
    for definition in (n for n in ast.walk(trees[path]) if isinstance(n, ast.FunctionDef) and n.name == function):
        for node, guards in _visit(definition):
            if guard is not None and guard not in guards:
                continue
            if isinstance(node, ast.If) and fragment in ast.unparse(node.test) and _refutes(node.body):
                return True
            if (
                isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "same"
                and any(fragment in ast.unparse(arg) for arg in node.args)
            ):
                return True
    return False


def _called_under(trees, path: str, callee: str, guard: str) -> bool:
    return any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == callee
        and guard in guards
        for node, guards in _visit(trees[path])
    )


def _names(expr: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(expr):
        if isinstance(node, ast.Name):
            names.add(node.id.lower())
        elif isinstance(node, ast.Attribute):
            names.add(node.attr.lower())
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            names.add(node.value.lower())
    return names


def _refuted_names(trees, object_id: str, tokens: tuple[str, ...]) -> bool:
    """Some refuting If in the object's owned sources tests a name that contains one of tokens."""
    for path in batch._OWNED_PATHS[object_id]:
        for node in ast.walk(trees[path]):
            if isinstance(node, ast.If) and _refutes(node.body):
                if any(token in name for token in tokens for name in _names(node.test)):
                    return True
    return False


ROOT_MECHANISMS = {
    "vstd-actor": lambda t: _decisive(
        t, D + "actor.py", "evaluate", "actor_components & instrument_components", "check == 'identity'"),
    "vstd-agent": lambda t: _decisive(
        t, D + "agent.py", "evaluate", "not in invocations", "check == 'actions'"),
    "vstd-bot": lambda t: (
        _decisive(t, D + "bot.py", "containment", "separation not in SEPARATIONS")
        and _called_under(t, D + "bot.py", "containment", "check == 'containment'")
        and _decisive(t, D + "bot.py", "loop", "observations[transition + 1]", "check == 'observation'")
        and _decisive(t, D + "bot.py", "loop", "actions[transition]", "not (check == 'observation')")
        and _called_under(t, D + "bot.py", "loop", "check != 'alignment'")
    ),
    "vstd-collective": lambda t: (
        _decisive(t, D + "collective.py", "_decisions", "component_roles != required[decision_class]")
        and _called_under(t, D + "collective.py", "_decisions", "check in ('decisions', 'quorum')")
    ),
    "vstd-benchmark": lambda t: _decisive(
        t, D + "bench.py", "evaluate", "score < expected", "scores"),
    "vstd-human": lambda t: _decisive(
        t, D + "human.py", "_assertion", "population.lower() in {'global', 'worldwide', 'all-humans', 'all humans'}"),
    "vstd-architecture": lambda t: _decisive(
        t, C + "arch_schedule.py", "_evaluate", "len(position) != len(nodes)"),
}

APPLIES_MECHANISMS = {
    ("vstd-actor", "POLICY"): lambda t: _decisive(
        t, D + "actor.py", "evaluate", "set(subset) <= set(decision_classes)", "check == 'delegation'"),
    ("vstd-collective", "LEDGER"): lambda t: (
        _decisive(t, C + "collective_closure.py", "_declared_ledger", "instant < previous")
        and _called_under(t, C + "collective_closure.py", "_declared_ledger", "status != 'PASS'")
    ),
    ("vstd-collective", "POLICY"): lambda t: (
        _decisive(t, D + "collective.py", "_decisions", "set(policy) != decision_classes")
        and _decisive(t, D + "collective.py", "_decisions", "component_roles != required[decision_class]")
        and _called_under(t, D + "collective.py", "_decisions", "check in ('decisions', 'quorum')")
    ),
    ("vstd-benchmark", "MEASUREMENT"): lambda t: _decisive(
        t, D + "bench.py", "evaluate", "not 0 <= run[field] <= problem[bound]", "check == 'budgets'"),
}


def _mechanism_failures(trees, rows) -> list[str]:
    """One failure per row whose status is not supported by its decisive source mechanism."""
    failures: list[str] = []
    for row in rows:
        label = f"{row.object_id} {row.role} {row.status}"
        key = (row.object_id, row.role)
        if row.role == batch.ROOT_ROLE:
            mechanism = ROOT_MECHANISMS.get(row.object_id)
            if mechanism is None or not mechanism(trees):
                failures.append("MECHANISM_ROOT_UNSUPPORTED " + label)
        elif row.status == "APPLIES":
            if key in APPLIES_MECHANISMS:
                holds = APPLIES_MECHANISMS[key](trees)
            elif row.role == "ACTUATOR":
                holds = _refuted_names(trees, row.object_id, EFFECT_TOKENS)
            elif row.role == "PROTOCOL":
                holds = _refuted_names(trees, row.object_id, LIVENESS_TOKENS)
            else:
                holds = False
            if not holds:
                failures.append("MECHANISM_UNSUPPORTED " + label)
        else:
            tokens = CONSEQUENCE_TOKENS.get(row.role)
            if tokens is None or not _refuted_names(trees, row.object_id, tokens):
                failures.append("MECHANISM_DNE_UNREFUTED " + label)
    return failures


# (predicate, path, exact decisive source line, disabled replacement).  The replacement keeps the
# old message as a comment, so a re-pinned marker is present; the predicate must still fail.
PREDICATE_MUTATIONS = (
    (ROOT_MECHANISMS["vstd-actor"], D + "actor.py",
     "if actor_components & instrument_components:",
     "if False:  # instrument boundary overlap: component on both sides"),
    (APPLIES_MECHANISMS[("vstd-actor", "POLICY")], D + "actor.py",
     "if not set(subset) <= set(decision_classes):",
     "if False:  # delegation conveys authority outside actor's decision classes"),
    (APPLIES_MECHANISMS[("vstd-actor", "POLICY")], D + "actor.py",
     'elif check == "delegation":',
     'elif check == "unlisted":  # delegation'),
    (ROOT_MECHANISMS["vstd-agent"], D + "agent.py",
     'if (text(action["tool"]), action["record"]) not in invocations:',
     "if False:  # declared action has no witnessed tool invocation in the bound harness"),
    (ROOT_MECHANISMS["vstd-bot"], D + "bot.py",
     "if separation not in SEPARATIONS:",
     "if False:  # environment separation must be distinct or fused"),
    (ROOT_MECHANISMS["vstd-bot"], D + "bot.py",
     'same(invocation["output"], observations[transition + 1],',
     'same(invocation["output"], observations[transition],'),
    (ROOT_MECHANISMS["vstd-bot"], D + "bot.py",
     'same(invocation["input"], actions[transition],',
     'same(invocation["input"], actions[0],'),
    (ROOT_MECHANISMS["vstd-bot"], D + "bot.py",
     'separation = containment(artifact, bound, budget) if check == "containment" else None',
     'separation = containment(artifact, bound, budget) if check == "unlisted" else None'),
    (APPLIES_MECHANISMS[("vstd-collective", "POLICY")], D + "collective.py",
     "if set(policy) != decision_classes:",
     "if False:  # collective assembly policy does not cover declared decision classes"),
    (ROOT_MECHANISMS["vstd-collective"], D + "collective.py",
     "if len(component_roles) != len(components) or component_roles != required[decision_class]:",
     "if False:  # collective decision violates its declared assembly policy"),
    (ROOT_MECHANISMS["vstd-collective"], D + "collective.py",
     'if check in ("decisions", "quorum"):',
     "if False:  # decisions"),
    (APPLIES_MECHANISMS[("vstd-collective", "LEDGER")], C + "collective_closure.py",
     'if row["decision_id"] in ledger or instant < previous or not selected["period_us"][0] <= instant < selected["period_us"][1]:',
     "if False:  # duplicate/order/time contradicts its exact claim"),
    (APPLIES_MECHANISMS[("vstd-collective", "LEDGER")], C + "collective_closure.py",
     'if status != "PASS":',
     "if False:  # freshly replayed ROLE closure prerequisite remains UNKNOWN"),
    (APPLIES_MECHANISMS[("vstd-benchmark", "MEASUREMENT")], D + "bench.py",
     "if problem[bound] <= 0 or not 0 <= run[field] <= problem[bound]:",
     "if False:  # retained benchmark resource observation exceeds bound"),
    (APPLIES_MECHANISMS[("vstd-benchmark", "MEASUREMENT")], D + "bench.py",
     'if check == "budgets":',
     "if False:  # budgets"),
    (ROOT_MECHANISMS["vstd-benchmark"], D + "bench.py",
     "if score < expected:",
     "if False:  # recomputed benchmark score below required threshold"),
    (ROOT_MECHANISMS["vstd-human"], D + "human.py",
     'if population.lower() in {"global", "worldwide", "all-humans", "all humans"}:',
     "if False:  # global person uniqueness cannot be established"),
    (ROOT_MECHANISMS["vstd-architecture"], C + "arch_schedule.py",
     "if len(position) != len(nodes):",
     "if False:  # schedule omits a retained graph node"),
)


# ---------------------------------------------------------------------------------------------
# Census, digest, owner, and batch-contract tests (unchanged obligations).
# ---------------------------------------------------------------------------------------------


def test_primary_kinds_and_identities_are_preserved():
    rows = {spec.object_id: spec.primary_kind for spec in batch.SEMANTIC_OWNERSHIP_SPECS}
    assert rows == {
        "vstd-actor": "ACTOR",
        "vstd-agent": "AGENT",
        "vstd-architecture": "ARCH",
        "vstd-benchmark": "BENCH",
        "vstd-bot": "BOT",
        "vstd-collective": "COLLECTIVE",
        "vstd-human": "HUMAN",
    }
    assert tuple(sorted(rows)) == tuple(spec.object_id for spec in batch.SEMANTIC_OWNERSHIP_SPECS)
    assert batch.PRIMARY_KINDS == tuple(sorted(set(rows.values())))


def test_census_is_exactly_the_25_declared_paths_under_domains():
    assert batch.PATH_CENSUS == tuple(sorted(EXPECTED_PATHS))
    assert len(batch.PATH_CENSUS) == 25
    assert all(path.startswith("src/verifier/domains/") for path in batch.PATH_CENSUS)
    owned = [path for spec in batch.SEMANTIC_OWNERSHIP_SPECS for path in spec.owned_paths]
    assert sorted(owned) == sorted(EXPECTED_PATHS)
    assert len(owned) == len(set(owned))


def test_owner_mapping_is_golden_no_wrong_owner_missing_or_extra_path():
    assert _owner_map(batch.SEMANTIC_OWNERSHIP_SPECS) == EXPECTED_OWNERS


def test_digest_census_matches_pinned_bytes_on_disk():
    assert batch.SOURCE_DIGESTS == {path: "sha256:" + digest for path, digest in EXPECTED_DIGESTS.items()}
    for path, digest in EXPECTED_DIGESTS.items():
        observed = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        assert observed == digest, path
    assert batch.source_drift_failures(ROOT, batch.PATH_CENSUS, batch.SOURCE_DIGESTS) == ()


def test_batch_validates_and_exports_standalone_tuple():
    specs = _validate()
    assert len(specs) == 7
    assert all(type(spec) is SemanticOwnershipSpec for spec in specs)
    assert all(spec.operands == batch._OPERAND_TARGETS.get(spec.object_id, ()) for spec in specs)
    assert specs == tuple(sorted(specs, key=lambda spec: spec.object_id))


def test_evidence_spans_ground_in_current_source_without_docstrings_or_comments():
    cited = (*batch.SOURCE_ROLE_DECISIONS, *batch.unresolved_records())
    assert batch.evidence_failures(ROOT, cited) == ()


def test_source_markers_occur_in_cited_lines():
    cited = (*batch.SOURCE_ROLE_DECISIONS, *batch.unresolved_records())
    assert batch.marker_failures(ROOT, cited) == ()


def test_decision_table_is_golden_and_specializations_follow_applies_only():
    by_object: dict[str, dict[str, list[str]]] = {}
    for row in batch.SOURCE_ROLE_DECISIONS:
        by_object.setdefault(row.object_id, {"APPLIES": [], "DOES_NOT_APPLY": []})
        if row.role != batch.ROOT_ROLE:
            by_object[row.object_id][row.status].append(row.role)
    for object_id, expected in EXPECTED_ROLES.items():
        assert tuple(sorted(by_object.get(object_id, {}).get("APPLIES", []))) == expected["APPLIES"], object_id
        assert tuple(sorted(by_object.get(object_id, {}).get("DOES_NOT_APPLY", []))) == expected["DOES_NOT_APPLY"], object_id
    for spec in batch.SEMANTIC_OWNERSHIP_SPECS:
        expected = set(EXPECTED_ROLES[spec.object_id]["APPLIES"])
        expected.update(batch.OBLIGATION_RETENTION_APPLIES.get(spec.object_id, ()))
        assert spec.specializations == tuple(sorted(expected)), spec.object_id
        assert all(root.kind == batch.ROOT_ROLE and root.status == "APPLIES"
                   for root in spec.root_role_decisions)


def test_unresolved_roles_are_unknown_not_exempt_and_partition_the_registry():
    unresolved = batch.unresolved_roles()
    for object_id, expected in EXPECTED_ROLES.items():
        decided = set(expected["APPLIES"]) | set(expected["DOES_NOT_APPLY"])
        decided.update(batch.OBLIGATION_RETENTION_APPLIES.get(object_id, ()))
        assert set(unresolved[object_id]) == set(batch.ACCUMULATING_ROLES) - decided, object_id
        assert set(unresolved[object_id]).isdisjoint(expected["APPLIES"])
    assert all(roles == () for roles in unresolved.values())


def test_bot_and_agent_never_source_inherit_robot_or_finbot_by_primary_kind():
    for object_id in ("vstd-bot", "vstd-agent"):
        roles = {row.role for row in batch.SOURCE_ROLE_DECISIONS if row.object_id == object_id}
        assert "ROBOT" not in roles and "FINBOT" not in roles, object_id
        spec = next(item for item in batch.SEMANTIC_OWNERSHIP_SPECS if item.object_id == object_id)
        assert {"ROBOT", "FINBOT"} <= set(batch.OBLIGATION_RETENTION_APPLIES[object_id])
        assert {"ROBOT", "FINBOT"} <= set(spec.specializations)


def test_no_placeholder_operands_and_blockers_match_namespace_layout():
    assert all(
        spec.operands == batch._OPERAND_TARGETS.get(spec.object_id, ())
        for spec in batch.SEMANTIC_OWNERSHIP_SPECS
    )
    assert "-unresolved" not in MODULE.read_text(encoding="utf-8").lower()
    assert batch.integration_blockers() == ()
    kinds = {"vstd-actor": "ACTOR", "vstd-agent": "AGENT", "vstd-bot": "BOT",
             "vstd-collective": "COLLECTIVE", "vstd-benchmark": "BENCH"}
    for object_id, kind in kinds.items():
        bound = {slot: targets for slot, targets in batch._OPERAND_TARGETS[object_id]}
        assert set(bound) == set(namespace._SLOTS[kind]), kind
        assert all(bound[slot] for slot in namespace._SLOTS[kind])


def test_aggregation_is_ready_when_every_typed_slot_is_exactly_bound():
    assert batch.integration_blockers() == ()
    assert batch.aggregation_ready() is True


def test_module_is_standalone_with_zero_runtime_dependencies():
    tree = ast.parse(MODULE.read_text(encoding="utf-8"), filename=str(MODULE))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert imported <= ALLOWED_IMPORTS


def test_exports_are_the_declared_surface():
    assert set(batch.__all__) == {
        "ACCUMULATING_ROLES", "DECIDED_ROLES", "OBLIGATION_RETENTION_APPLIES", "PATH_CENSUS", "PRIMARY_KINDS", "ROOT_APPLICABILITY",
        "ROOT_ROLE", "SEMANTIC_OWNERSHIP_SPECS", "SOURCE_DIGESTS", "SOURCE_ROLE_DECISIONS", "SourceEvidence",
        "SourceRoleDecision", "SourceRoleUnresolved", "UNKNOWN", "aggregation_ready", "evidence_failures",
        "integration_blockers", "marker_failures", "obligation_retention_reason", "source_digest", "source_drift_failures",
        "unresolved_records", "unresolved_roles", "validate_batch",
    }


# ---------------------------------------------------------------------------------------------
# Mechanism gate: every decision row is accepted only by its source-mechanism predicate.
# ---------------------------------------------------------------------------------------------


def test_decision_table_is_accepted_only_by_source_mechanism_predicates():
    assert _mechanism_failures(_real_trees(), batch.SOURCE_ROLE_DECISIONS) == []


def test_every_decision_declares_applicability_next_action_and_an_executable_checker():
    for row in batch.SOURCE_ROLE_DECISIONS:
        assert getattr(row, "applicability", "").strip(), (row.object_id, row.role)
        assert getattr(row, "next_action", "").strip(), (row.object_id, row.role)
        checker = getattr(row, "checker", "")
        assert callable(_declared_checker(checker)), (row.object_id, row.role, checker)


def test_every_unknown_cell_has_a_record_with_reason_next_action_and_checker():
    assert hasattr(batch, "unresolved_records"), "unresolved_records() is absent"
    records = {(r.object_id, r.role): r for r in batch.unresolved_records()}
    cells = {(obj, role) for obj, roles in batch.unresolved_roles().items() for role in roles}
    assert set(records) == cells
    for key, record in records.items():
        assert record.reason.strip() and record.next_action.strip(), key
        assert callable(_declared_checker(record.checker)), (key, record.checker)


# ---------------------------------------------------------------------------------------------
# RED-first mutant kills.  Each names one confirmed wrong-reason class.  The eight classes are
# reconstructed from the confirmed repair list: (1) AGENT ACTUATOR APPLIES, (2) BOT ACTUATOR
# APPLIES, (3) COLLECTIVE PROTOCOL APPLIES, (4) HUMAN CONTROLLER DNE, (5) ACTOR ACTUATOR DNE,
# (6) COLLECTIVE closed-schema DNE, (7) BENCH closed-schema DNE, (8) closed-key-only DNE rule.
# ---------------------------------------------------------------------------------------------


def test_mutant_1_agent_actuator_retention_is_not_invocation_match_evidence():
    # Invocation comparison is not an effect endpoint or source role decision; the
    # separate reasons.vstd choice only retains the obligation.
    assert _status("vstd-agent", "ACTUATOR") is None
    assert _unknown_record("vstd-agent", "ACTUATOR") is None
    assert "ACTUATOR" in batch.OBLIGATION_RETENTION_APPLIES["vstd-agent"]


def test_compiler_reviews_adopt_every_conservative_obligation_retention():
    """The registry compiler must not refute a role the sole ledger retains.

    These APPLIES decisions retain obligations only.  They are deliberately
    distinct from SOURCE_ROLE_DECISIONS and therefore make no source-mechanism
    or external-effect claim.
    """
    from verifier.runtime import package_original_review_computation as computation
    from verifier.runtime import package_original_review_people as people
    from verifier.runtime import package_original_review_systems as systems

    compiled = {
        **people.review_document(),
        **systems.review_document(),
        **computation.review_document(),
    }
    assert set(batch.OBLIGATION_RETENTION_APPLIES) <= set(compiled)
    for object_id, kinds in batch.OBLIGATION_RETENTION_APPLIES.items():
        for kind in kinds:
            decision = compiled[object_id]["classification"][kind]
            assert decision["status"] == "APPLIES", (object_id, kind, decision)


def test_mutant_2_bot_actuator_applies_is_unknown_not_replayed_action_list():
    # Comparing retained simulated action lists is neither real actuation nor an executed transition.
    _assert_retained_not_source("vstd-bot", "ACTUATOR")


def test_mutant_3_collective_protocol_applies_is_unknown_without_failure_or_liveness():
    # Order, quorum and class checks are not failure or liveness participant protocol semantics.
    _assert_retained_not_source("vstd-collective", "PROTOCOL")


def test_mutant_4_human_controller_dne_is_unknown_without_feedback_law_refutation():
    _assert_retained_not_source("vstd-human", "CONTROLLER")


def test_mutant_5_actor_actuator_dne_is_unknown_not_boundary_overlap():
    # An instrument-boundary overlap refutation does not refute an actuator.
    _assert_retained_not_source("vstd-actor", "ACTUATOR")


@pytest.mark.parametrize("role", ("ROBOT", "FINBOT", "ACTUATOR"))
def test_mutant_6_collective_closed_schema_dne_is_unknown(role):
    _assert_retained_not_source("vstd-collective", role)


@pytest.mark.parametrize("role", ("ACTUATOR", "ROBOT", "FINBOT"))
def test_mutant_7_bench_closed_schema_dne_is_unknown(role):
    _assert_retained_not_source("vstd-benchmark", role)


def test_mutant_8_closed_key_only_dne_fails_closed():
    # Every DNE row on the real table must carry its refuting mechanism; closed keys are not one.
    dne_rows = [row for row in batch.SOURCE_ROLE_DECISIONS if row.status == "DOES_NOT_APPLY"]
    assert _mechanism_failures(_real_trees(), dne_rows) == []


def test_closed_key_only_dne_injection_is_rejected_by_the_mechanism_gate():
    injected = batch.SourceRoleDecision(
        object_id="vstd-collective",
        role="ROBOT",
        status="DOES_NOT_APPLY",
        evidence=(batch.SourceEvidence(D + "collective.py", "_decisions", 78, 78, "bearer_id"),),
        reason="collective.py _decisions closed exact-key schema carries no consequence field.",
        applicability="CONDITIONAL: check in ('decisions', 'quorum')",
        next_action="none",
        checker="test_decision_table_is_golden_and_specializations_follow_applies_only",
    )
    assert _mechanism_failures(_real_trees(), (injected,)) == [
        "MECHANISM_DNE_UNREFUTED vstd-collective ROBOT DOES_NOT_APPLY",
    ]


def test_controller_dne_injection_needs_a_feedback_law_refutation():
    # HUMAN closed lifecycle keys carry no control signal, so a DOES_NOT_APPLY CONTROLLER fails closed.
    injected = batch.SourceRoleDecision(
        object_id="vstd-human", role="CONTROLLER", status="DOES_NOT_APPLY",
        evidence=(batch.SourceEvidence(D + "human.py", "evaluate", 73, 73, '"evidence_id", "instrument"'),),
        reason="human.py evaluate closed lifecycle keys carry no control field.",
        applicability="CONDITIONAL: check == 'lifecycle'", next_action="none",
        checker="test_human_evidence_cites_executable_mechanism_not_prose_literals",
    )
    assert _mechanism_failures(_real_trees(), (injected,)) == [
        "MECHANISM_DNE_UNREFUTED vstd-human CONTROLLER DOES_NOT_APPLY",
    ]


def test_applies_actuator_and_protocol_injection_need_effect_and_liveness_refutations():
    agent_actuator = batch.SourceRoleDecision(
        object_id="vstd-agent", role="ACTUATOR", status="APPLIES",
        evidence=(batch.SourceEvidence(D + "agent.py", "evaluate", 63, 65, "not in invocations"),),
        reason="agent.py evaluate invocation comparison.", applicability="CONDITIONAL: check == 'actions'",
        next_action="none", checker="test_decision_table_is_golden_and_specializations_follow_applies_only",
    )
    protocol = batch.SourceRoleDecision(
        object_id="vstd-collective", role="PROTOCOL", status="APPLIES",
        evidence=(batch.SourceEvidence(C + "collective_closure.py", "_evaluate", 366, 366, "not in members"),),
        reason="collective_closure.py _evaluate membership check.",
        applicability="CONDITIONAL: classes is not None", next_action="none",
        checker="test_decision_table_is_golden_and_specializations_follow_applies_only",
    )
    assert _mechanism_failures(_real_trees(), (agent_actuator, protocol)) == [
        "MECHANISM_UNSUPPORTED vstd-agent ACTUATOR APPLIES",
        "MECHANISM_UNSUPPORTED vstd-collective PROTOCOL APPLIES",
    ]


# ---------------------------------------------------------------------------------------------
# Preserved APPLIES: audited explicitly.  Each has a decisive, guarded source condition.
# ---------------------------------------------------------------------------------------------


def test_preserved_applies_are_audited_with_decisive_conditions():
    for key, predicate in APPLIES_MECHANISMS.items():
        assert predicate(_real_trees()) is True, key
    ledger = _row("vstd-collective", "LEDGER")
    assert ledger is not None
    # The ledger is reached only when the freshly replayed ROLE closure is neither PASS nor FAIL.
    assert "PASS" in ledger.applicability and "FAIL" in ledger.applicability, ledger.applicability
    policy = _row("vstd-collective", "POLICY")
    assert policy is not None and "check in ('decisions', 'quorum')" in policy.applicability
    measurement = _row("vstd-benchmark", "MEASUREMENT")
    assert measurement is not None and "budgets" in measurement.applicability
    actor_policy = _row("vstd-actor", "POLICY")
    assert actor_policy is not None and "check == 'delegation'" in actor_policy.applicability


# ---------------------------------------------------------------------------------------------
# Root applicability: exact batch-local mapping, executable tokens, and no message-text markers.
# ---------------------------------------------------------------------------------------------

ROOT_REASON_TOKENS = {
    "vstd-actor": "actor_components & instrument_components",
    "vstd-agent": "not in invocations",
    "vstd-bot": "separation not in SEPARATIONS",
    "vstd-collective": "component_roles != required[decision_class]",
    "vstd-benchmark": "score < expected",
    "vstd-human": "population.lower() in",
    "vstd-architecture": "len(position) != len(nodes)",
}


def test_root_applicability_is_an_exact_batch_local_mapping():
    mapping = getattr(batch, "ROOT_APPLICABILITY", None)
    assert mapping == {object_id: "APPLIES" for object_id in batch._OWNED_PATHS}


def test_unknown_root_is_exported_with_no_root_decision(monkeypatch):
    # An UNKNOWN root cannot be encoded in the shared RootRoleDecision type, so it exports none.
    mapping = {**batch.ROOT_APPLICABILITY, "vstd-human": "UNKNOWN"}
    monkeypatch.setattr(batch, "ROOT_APPLICABILITY", mapping)
    specs = tuple(batch._row(object_id) for object_id in sorted(batch._OWNED_PATHS))
    decisions = tuple(
        row for row in batch.SOURCE_ROLE_DECISIONS
        if (row.object_id, row.role) != ("vstd-human", batch.ROOT_ROLE)
    )
    exported = {spec.object_id: spec for spec in _validate(specs, decisions)}
    assert exported["vstd-human"].root_role_decisions == ()
    assert exported["vstd-actor"].root_role_decisions != ()


def test_root_status_outside_the_exact_mapping_is_rejected():
    actor = next(spec for spec in batch.SEMANTIC_OWNERSHIP_SPECS if spec.object_id == "vstd-actor")
    altered = dataclasses.replace(
        actor,
        root_role_decisions=(root_role_decision("VERIFIER", "DOES_NOT_APPLY", actor.root_role_decisions[0].reason),),
    )
    specs = tuple(altered if spec is actor else spec for spec in batch.SEMANTIC_OWNERSHIP_SPECS)
    decisions = tuple(
        dataclasses.replace(row, status="DOES_NOT_APPLY")
        if row.object_id == "vstd-actor" and row.role == batch.ROOT_ROLE else row
        for row in batch.SOURCE_ROLE_DECISIONS
    )
    _expect("BATCH_ROOT_ROLE_INVALID", _validate, specs, decisions)


def test_root_markers_are_executable_tokens_not_refuted_message_text():
    for row in batch.SOURCE_ROLE_DECISIONS:
        if row.role != batch.ROOT_ROLE:
            continue
        for span in row.evidence:
            messages = _call_string_args(span.path, span.start_line, span.end_line)
            assert not any(span.marker in message for message in messages), (row.object_id, span.marker)


def test_root_reasons_cite_their_executable_condition_token():
    for object_id, token in ROOT_REASON_TOKENS.items():
        root = _row(object_id, batch.ROOT_ROLE)
        assert root is not None and token in root.reason, (object_id, token)


def test_bot_root_cites_real_separation_and_loop_checks():
    root = _row("vstd-bot", batch.ROOT_ROLE)
    assert root is not None
    assert "observations[transition + 1]" in root.reason and "separation not in SEPARATIONS" in root.reason
    cited = {(span.symbol, span.marker) for span in root.evidence}
    assert ("containment", "separation not in SEPARATIONS") in cited
    assert ("loop", "observations[transition + 1]") in cited


def test_human_root_is_limited_to_its_denylist():
    root = _row("vstd-human", batch.ROOT_ROLE)
    assert root is not None
    reason = root.reason.lower()
    assert "denylist" in reason
    for literal in ("global", "worldwide", "all-humans", "all humans"):
        assert literal in reason, literal
    assert "global person uniqueness" not in reason


def test_root_mechanisms_hold_on_real_source():
    for object_id, predicate in ROOT_MECHANISMS.items():
        assert predicate(_real_trees()) is True, object_id


# ---------------------------------------------------------------------------------------------
# Mutation oracles: disabling any decisive condition fails its predicate, even with its old
# message kept as a comment.  Each mutation must change exactly one source line.
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("predicate", "path", "old", "new"),
    PREDICATE_MUTATIONS,
    ids=[f"{index:02d}-{entry[2][:48]}" for index, entry in enumerate(PREDICATE_MUTATIONS)],
)
def test_disabling_the_decisive_condition_fails_its_predicate(predicate, path, old, new):
    source = (ROOT / path).read_text(encoding="utf-8")
    assert source.count(old) == 1, (path, old)
    mutated = ast.parse(source.replace(old, new), filename=path)
    assert predicate(_real_trees()) is True, (path, old)
    assert predicate({**_real_trees(), path: mutated}) is False, (path, old)


def test_shifting_source_lines_breaks_markers_even_when_spans_still_parse(tmp_path):
    for path in batch.PATH_CENSUS:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / path, target)
    agent = tmp_path / D / "agent.py"
    agent.write_text("# shifted by two lines\n# shifted by two lines\n" + agent.read_text(encoding="utf-8"),
                     encoding="utf-8")
    assert batch.evidence_failures(tmp_path, batch.SOURCE_ROLE_DECISIONS) == ()
    failures = batch.marker_failures(tmp_path, batch.SOURCE_ROLE_DECISIONS)
    assert any("vstd-agent" in item for item in failures)


# ---------------------------------------------------------------------------------------------
# Adversarial batch contracts (unchanged obligations).
# ---------------------------------------------------------------------------------------------


def test_census_missing_path_is_rejected():
    census = tuple(path for path in batch.PATH_CENSUS if path != D + "bot.py")
    digests = {path: batch.SOURCE_DIGESTS[path] for path in census}
    _expect("BATCH_CENSUS_NOT_EXACT", _validate, None, None, census, digests)


def test_census_extra_path_is_rejected():
    extra = D + "extra.py"
    census = tuple(sorted((*batch.PATH_CENSUS, extra)))
    digests = {**batch.SOURCE_DIGESTS, extra: "sha256:" + "0" * 64}
    _expect("BATCH_CENSUS_NOT_EXACT", _validate, None, None, census, digests)


def test_duplicate_path_across_rows_is_rejected():
    agent_paths = next(spec.owned_paths for spec in batch.SEMANTIC_OWNERSHIP_SPECS if spec.object_id == "vstd-agent")
    specs = _replace_row("vstd-agent", owned_paths=tuple(sorted((*agent_paths, D + "actor.py"))))
    _expect("BATCH_PATH_DUPLICATED", _validate, specs)


def test_path_moved_to_wrong_owner_is_caught_by_golden_map_and_rejected():
    actor = next(spec for spec in batch.SEMANTIC_OWNERSHIP_SPECS if spec.object_id == "vstd-actor")
    agent = next(spec for spec in batch.SEMANTIC_OWNERSHIP_SPECS if spec.object_id == "vstd-agent")
    moved = tuple(
        dataclasses.replace(spec, owned_paths=tuple(p for p in spec.owned_paths if p != D + "actor.py"))
        if spec is actor else
        dataclasses.replace(spec, owned_paths=tuple(sorted((*spec.owned_paths, D + "actor.py"))))
        if spec is agent else spec
        for spec in batch.SEMANTIC_OWNERSHIP_SPECS
    )
    assert _owner_map(moved) != EXPECTED_OWNERS
    with pytest.raises(ValueError):
        _validate(specs=moved)


def test_role_promotion_without_evidence_is_rejected():
    decisions = (*batch.SOURCE_ROLE_DECISIONS, _decision("vstd-bot", "ROBOT", evidence=()))
    _expect("BATCH_DECISION_EVIDENCE_REQUIRED", _validate, None, decisions)


def test_refutation_by_primary_kind_without_bound_evidence_is_rejected():
    bad = _decision(
        "vstd-bot", "ROBOT", "DOES_NOT_APPLY",
        evidence=(batch.SourceEvidence(D + "bot.py", "containment", 109, 110,
                                       "separation not in SEPARATIONS"),),
        reason="BOT is simulation-situated, so no robot consequence applies.",
    )
    decisions = tuple(
        row for row in batch.SOURCE_ROLE_DECISIONS
        if not (row.object_id == "vstd-bot" and row.role == "ROBOT")
    ) + (bad,)
    _expect("BATCH_DECISION_REASON_UNBOUND", _validate, None, decisions)


def test_object_fallback_role_is_rejected():
    fallback = _decision("vstd-human", "OBJECT", "APPLIES")
    _expect("BATCH_DECISION_ROLE_INVALID", _validate, None, (*batch.SOURCE_ROLE_DECISIONS, fallback))


def test_specialization_without_its_decision_is_rejected_unknown_is_not_exempt():
    actor = next(spec for spec in batch.SEMANTIC_OWNERSHIP_SPECS if spec.object_id == "vstd-actor")
    promoted = dataclasses.replace(actor, specializations=("POLICY", "ROBOT"))
    specs = tuple(promoted if spec is actor else spec for spec in batch.SEMANTIC_OWNERSHIP_SPECS)
    _expect("BATCH_ROLE_PROMOTION_MISMATCH", _validate, specs)


def test_applies_decision_absent_from_specializations_is_rejected():
    arch = next(
        spec for spec in batch.SEMANTIC_OWNERSHIP_SPECS
        if spec.object_id == "vstd-architecture"
    )
    missing = dataclasses.replace(
        arch,
        specializations=tuple(
            role for role in arch.specializations if role != "MEASUREMENT"
        ),
    )
    specs = tuple(
        missing if spec is arch else spec
        for spec in batch.SEMANTIC_OWNERSHIP_SPECS
    )
    _expect("BATCH_ROLE_PROMOTION_MISMATCH", _validate, specs)


def test_placeholder_operand_is_rejected():
    bench = next(spec for spec in batch.SEMANTIC_OWNERSHIP_SPECS if spec.object_id == "vstd-benchmark")
    placeholder = dataclasses.replace(
        bench, operands=(("data", ("vstd-benchmark-unresolved-data",)),)
    )
    specs = tuple(placeholder if spec is bench else spec for spec in batch.SEMANTIC_OWNERSHIP_SPECS)
    _expect("BATCH_OPERAND_BINDING_INVALID", _validate, specs)


def test_root_role_decision_must_match_the_decision_table():
    actor = next(spec for spec in batch.SEMANTIC_OWNERSHIP_SPECS if spec.object_id == "vstd-actor")
    altered = dataclasses.replace(
        actor,
        root_role_decisions=(root_role_decision("VERIFIER", "APPLIES", "actor.py changed reason."),),
    )
    specs = tuple(altered if spec is actor else spec for spec in batch.SEMANTIC_OWNERSHIP_SPECS)
    _expect("BATCH_ROOT_ROLE_UNDECIDED", _validate, specs)


def test_orphan_decision_for_unknown_object_is_rejected():
    orphan = _decision("vstd-ghost", "POLICY", "APPLIES")
    _expect("BATCH_DECISION_OBJECT_UNKNOWN", _validate, None, (*batch.SOURCE_ROLE_DECISIONS, orphan))


def test_docstring_evidence_cannot_ground_a_decision():
    # bot.py line 19 is the docstring of ``parts``.
    span = batch.SourceEvidence(D + "bot.py", "parts", 19, 19, "Re-derive every bound certificate")
    decision = _decision("vstd-bot", "CONTROLLER", "APPLIES", evidence=(span,),
                         reason="bot.py parts docstring claims a controller.")
    failures = batch.evidence_failures(ROOT, (decision,))
    assert any(item.startswith("EVIDENCE_IS_DOCSTRING") for item in failures)


def test_comment_evidence_cannot_ground_a_decision():
    # actor.py line 29 is a comment inside ``evaluate``.
    span = batch.SourceEvidence(D + "actor.py", "evaluate", 29, 29, "identity")
    decision = _decision("vstd-actor", "POLICY", "APPLIES", evidence=(span,),
                         reason="actor.py evaluate comment claims a policy.")
    failures = batch.evidence_failures(ROOT, (decision,))
    assert any(item.startswith("EVIDENCE_IS_COMMENT") for item in failures)


def test_missing_symbol_and_out_of_symbol_spans_are_rejected():
    missing = batch.SourceEvidence(D + "bench.py", "no_such_function", 10, 10, "x")
    outside = batch.SourceEvidence(D + "bench.py", "_rational", 40, 40, "x")
    decisions = (
        _decision("vstd-benchmark", "MEASUREMENT", "APPLIES", evidence=(missing,),
                  reason="bench.py missing symbol."),
        _decision("vstd-benchmark", "ROBOT", "DOES_NOT_APPLY", evidence=(outside,),
                  reason="bench.py outside symbol."),
    )
    failures = batch.evidence_failures(ROOT, decisions)
    assert any(item.startswith("EVIDENCE_SYMBOL_MISSING") for item in failures)
    assert any(item.startswith("EVIDENCE_OUTSIDE_SYMBOL") for item in failures)


def test_marker_mismatch_is_reported():
    span = batch.SourceEvidence(D + "human.py", "_assertion", 30, 31, "not a source marker")
    decision = _decision("vstd-human", "ROBOT", "DOES_NOT_APPLY", evidence=(span,),
                         reason="human.py marker mismatch.")
    assert any("EVIDENCE_MARKER_MISSING" in item for item in batch.marker_failures(ROOT, (decision,)))


def test_byte_drift_in_a_copied_tree_is_detected(tmp_path):
    for path in batch.PATH_CENSUS:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / path, target)
    assert batch.source_drift_failures(tmp_path, batch.PATH_CENSUS, batch.SOURCE_DIGESTS) == ()
    bot = tmp_path / D / "bot.py"
    bot.write_bytes(bot.read_bytes() + b"\n# drift\n")
    failures = batch.source_drift_failures(tmp_path, batch.PATH_CENSUS, batch.SOURCE_DIGESTS)
    assert len(failures) == 1 and failures[0].startswith("SOURCE_DRIFT " + D + "bot.py")


def test_missing_census_file_is_reported(tmp_path):
    failures = batch.source_drift_failures(tmp_path, batch.PATH_CENSUS, batch.SOURCE_DIGESTS)
    assert len(failures) == len(batch.PATH_CENSUS)
    assert all(item.startswith("SOURCE_MISSING ") for item in failures)


# ---------------------------------------------------------------------------------------------
# UNKNOWN records: each pins its cell's reason, next action and checker.
# ---------------------------------------------------------------------------------------------


def test_bot_controller_is_unknown_not_applies_by_runtime_limits_or_routing():
    applies = {(r.object_id, r.role) for r in batch.SOURCE_ROLE_DECISIONS if r.status == "APPLIES"}
    assert ("vstd-bot", "CONTROLLER") not in applies
    _assert_retained_not_source("vstd-bot", "CONTROLLER")


def test_arch_roles_are_retained_without_inheriting_from_the_scope_label():
    arch_rows = [r for r in batch.SOURCE_ROLE_DECISIONS if r.object_id == "vstd-architecture" and r.role != batch.ROOT_ROLE]
    assert arch_rows == []
    for role in ("ACTUATOR", "CONTROLLER", "ROBOT", "FINBOT"):
        _assert_retained_not_source("vstd-architecture", role)
    for row in batch.SOURCE_ROLE_DECISIONS:
        assert all(span.symbol != "SCOPE" for span in row.evidence), (row.object_id, row.role)


def test_transaction_is_never_dna_by_absence_of_commit_or_retry_fields():
    # No source role decision is inferred from absent atomicity fields.  The sole
    # reasons.vstd choice retains TRANSACTION without asserting a mechanism.
    assert [r for r in batch.SOURCE_ROLE_DECISIONS if r.role == "TRANSACTION"] == []
    for object_id in batch._OWNED_PATHS:
        _assert_retained_not_source(object_id, "TRANSACTION")


def test_human_absence_of_controller_actuator_robot_finbot_is_retained_not_silence_based_dna():
    for role in ("CONTROLLER", "ACTUATOR", "ROBOT", "FINBOT"):
        _assert_retained_not_source("vstd-human", role)


def test_human_evidence_cites_executable_mechanism_not_prose_literals():
    # A marker copied from a multi-word message literal is a prose label, not a mechanism token.
    for row in batch.SOURCE_ROLE_DECISIONS:
        if row.object_id != "vstd-human":
            continue
        for span in row.evidence:
            prose = [value for value in _string_constants(span.path, span.start_line, span.end_line) if " " in value]
            assert not any(span.marker in value for value in prose), (row.role, span.marker)


def test_bot_boundary_does_not_exempt_robot_finbot_actuator_or_controller_by_simulation_label():
    boundary = next(s for s in batch.SEMANTIC_OWNERSHIP_SPECS if s.object_id == "vstd-bot").consequence_boundary
    assert "no ROBOT or FINBOT consequence is inherited" not in boundary
    assert "UNKNOWN" in boundary and "ACTUATOR" in boundary


def test_unknown_cell_count_is_recomputed_from_records_not_from_decision_rows():
    accumulating = set(batch.ACCUMULATING_ROLES)
    decided = {(r.object_id, r.role) for r in batch.SOURCE_ROLE_DECISIONS if r.role != batch.ROOT_ROLE}
    retained = {
        (object_id, role)
        for object_id, roles in batch.OBLIGATION_RETENTION_APPLIES.items()
        for role in roles
    }
    unresolved = {(obj, role) for obj, roles in batch.unresolved_roles().items() for role in roles}
    assert decided.isdisjoint(unresolved)
    assert retained.isdisjoint(decided | unresolved)
    assert len(decided) + len(retained) + len(unresolved) == len(batch._OWNED_PATHS) * len(accumulating)
    assert len(unresolved) != len(batch.SOURCE_ROLE_DECISIONS)


def test_bench_measurement_is_conditional_on_the_budgets_check():
    row = _row("vstd-benchmark", "MEASUREMENT")
    assert row is not None
    assert row.applicability.startswith("CONDITIONAL") and "budgets" in row.applicability


def test_bench_transaction_is_retained_without_atomicity_evidence():
    _assert_retained_not_source("vstd-benchmark", "TRANSACTION")


def test_bot_and_agent_naming_does_not_make_the_verifier_the_object():
    pattern = re.compile(r"\b(is|are)\s+(a|an|the)?\s*(bot|agent|robot|finbot)\b", re.IGNORECASE)
    for object_id in ("vstd-bot", "vstd-agent"):
        root = _row(object_id, batch.ROOT_ROLE)
        assert root is not None and pattern.search(root.reason) is None, object_id
