from __future__ import annotations

import ast
from collections import Counter
from copy import deepcopy
from dataclasses import replace
from functools import lru_cache
from hashlib import sha256
import json
from pathlib import Path
import re

import pytest

from verifier.runtime.package_original_kind_catalog_experiments_hardware import (
    BEHAVIOR_OVERLAY,
    EFFECTIVE_TOTALS,
    EXPERIMENTS_HARDWARE_ORIGINAL_KIND_AUDITS,
    EXPERIMENTS_HARDWARE_PARTIAL_PROFILE,
    OVERLAY_DOWNGRADE_TOTALS,
    OVERLAY_TOTALS,
    PRIOR_OVERLAY_DNE_CLAIMS,
    UNRESOLVED,
    _overlay_check,
    current_source_partition,
    effective_review_document,
    review_document,
    validate_source_partition,
)
from verifier.runtime.package_original_kind_profiles import (
    APPLIES,
    DOES_NOT_APPLY,
    ORIGINAL_NON_OBJECT_KINDS,
    profile_digest,
    validate_profile,
)
from verifier.runtime.package_original_kind_review import apply_original_kind_profile
from verifier.runtime.package_semantic_ownership_model import RootRoleDecision


REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_SOURCE = (
    REPO_ROOT
    / "src"
    / "verifier"
    / "runtime"
    / "package_original_kind_catalog_experiments_hardware.py"
)


def _source_map():
    return {spec.object_id: spec for spec in current_source_partition()}


def test_exact_partition_denominator_and_literal_question_matrix() -> None:
    rows = EXPERIMENTS_HARDWARE_ORIGINAL_KIND_AUDITS
    assert len(rows) == 62
    assert len({row.object_id for row in rows}) == 62
    assert sum(row.group == "experiments" for row in rows) == 30
    assert sum(row.group == "hardware-interop" for row in rows) == 32
    assert all(
        tuple(question.kind for question in row.questions)
        == ORIGINAL_NON_OBJECT_KINDS
        for row in rows
    )

    source = CATALOG_SOURCE.read_text(encoding="utf-8")
    literal_catalog = source.split(
        "EXPERIMENTS_HARDWARE_ORIGINAL_KIND_AUDITS = (", 1
    )[1].split("EXPERIMENTS_HARDWARE_PARTIAL_PROFILE =", 1)[0]
    assert literal_catalog.count('_question("') == 62 * 25
    assert literal_catalog.count(", DOES_NOT_APPLY, ") == 27
    assert "for kind in" not in literal_catalog
    assert "difference(" not in literal_catalog


def test_current_partition_and_all_owned_paths_match_current_source() -> None:
    selected = current_source_partition()
    assert validate_source_partition(selected) == selected
    assert len(selected) == 62
    assert tuple(spec.object_id for spec in selected) == tuple(
        row.object_id for row in EXPERIMENTS_HARDWARE_ORIGINAL_KIND_AUDITS
    )
    assert sum(len(spec.owned_paths) for spec in selected) == 111
    assert [
        path
        for spec in selected
        for path in spec.owned_paths
        if not (REPO_ROOT / path).is_file()
    ] == []


def test_applies_and_exclusions_are_exact_cumulative_source_decisions() -> None:
    source = _source_map()
    applies = 0
    exclusions = 0
    unresolved = 0
    for row in EXPERIMENTS_HARDWARE_ORIGINAL_KIND_AUDITS:
        spec = source[row.object_id]
        expected_applies = set()
        if spec.primary_kind in ORIGINAL_NON_OBJECT_KINDS:
            expected_applies.add(spec.primary_kind)
        expected_applies.update(
            kind
            for kind in spec.specializations
            if kind in ORIGINAL_NON_OBJECT_KINDS
        )
        expected_applies.update(
            decision.kind
            for decision in spec.root_role_decisions
            if decision.kind in ORIGINAL_NON_OBJECT_KINDS
            and decision.status == APPLIES
        )
        expected_dne = {
            decision.kind: decision.reason
            for decision in spec.root_role_decisions
            if decision.kind in ORIGINAL_NON_OBJECT_KINDS
            and decision.status == DOES_NOT_APPLY
        }
        actual_applies = {
            question.kind
            for question in row.questions
            if question.status == APPLIES
        }
        actual_dne = {
            question.kind: question.reason
            for question in row.questions
            if question.status == DOES_NOT_APPLY
        }
        assert actual_applies == expected_applies
        assert set(actual_dne) == set(expected_dne)
        for kind, source_reason in expected_dne.items():
            assert source_reason in actual_dne[kind]
        applies += len(actual_applies)
        exclusions += len(actual_dne)
        unresolved += sum(
            question.status == UNRESOLVED for question in row.questions
        )
    assert (applies, exclusions, unresolved) == (105, 27, 1418)


def test_partial_profile_is_sealed_and_binds_all_decided_rows() -> None:
    profile = EXPERIMENTS_HARDWARE_PARTIAL_PROFILE
    assert validate_profile(profile) is profile
    assert profile_digest(profile) == profile.canonical_digest
    assert len(profile.assignments) == 50
    audits = {
        row.object_id: row for row in EXPERIMENTS_HARDWARE_ORIGINAL_KIND_AUDITS
    }
    for assignment in profile.assignments:
        row = audits[assignment.object_id]
        assert assignment.expected_primary == row.expected_primary
        assert assignment.expected_owned_paths == row.expected_owned_paths
        assert assignment.expected_owned_path_set_digest == (
            row.expected_owned_path_set_digest
        )
        assert assignment.decisions
        assert {
            (decision.kind, decision.status) for decision in assignment.decisions
        } == {
            (question.kind, question.status)
            for question in row.questions
            if question.status in {APPLIES, DOES_NOT_APPLY}
        }


def test_denominator_and_object_substitutions_fail_closed() -> None:
    selected = current_source_partition()
    with pytest.raises(
        ValueError, match="EXPERIMENTS_HARDWARE_SOURCE_DENOMINATOR_DRIFT"
    ):
        validate_source_partition(selected[:-1])

    substituted = list(selected)
    substituted[0] = replace(
        substituted[0], object_id=substituted[1].object_id
    )
    with pytest.raises(
        ValueError, match="EXPERIMENTS_HARDWARE_SOURCE_PARTITION_INVALID"
    ):
        validate_source_partition(substituted)


def test_path_primary_reason_and_role_substitutions_fail_closed() -> None:
    selected = list(current_source_partition())
    target = selected[0]
    index = selected.index(target)

    selected[index] = replace(
        target, owned_paths=("src/verifier/runtime/substituted.py",)
    )
    with pytest.raises(ValueError, match="SOURCE_PATH_DRIFT"):
        validate_source_partition(selected)

    selected[index] = replace(target, primary_kind="OBJECT")
    with pytest.raises(ValueError, match="SOURCE_PRIMARY_DRIFT"):
        validate_source_partition(selected)

    selected[index] = replace(target, necessity_reason="substituted reason")
    with pytest.raises(ValueError, match="SOURCE_COORDINATE_DRIFT"):
        validate_source_partition(selected)

    selected[index] = replace(target, representation_role="substituted role")
    with pytest.raises(ValueError, match="SOURCE_COORDINATE_DRIFT"):
        validate_source_partition(selected)


def test_conflicting_accumulated_role_decisions_hard_fail() -> None:
    selected = list(current_source_partition())
    target = next(spec for spec in selected if spec.primary_kind == "VERIFIER")
    index = selected.index(target)
    selected[index] = replace(
        target,
        root_role_decisions=target.root_role_decisions
        + (
            RootRoleDecision(
                "VERIFIER",
                DOES_NOT_APPLY,
                "counterexample exclusion conflicting with primary",
            ),
        ),
    )
    with pytest.raises(ValueError, match="SOURCE_ROLE_CONFLICT"):
        validate_source_partition(selected)


def test_object_relabel_never_bypasses_original_kind_review() -> None:
    selected = list(current_source_partition())
    target = next(spec for spec in selected if spec.primary_kind == "POLICY")
    index = selected.index(target)
    selected[index] = replace(target, primary_kind="OBJECT")
    with pytest.raises(ValueError, match="SOURCE_PRIMARY_DRIFT"):
        validate_source_partition(selected)

    document = review_document()
    assert len(document) == 62
    assert all(
        tuple(entry["questions"]) == ORIGINAL_NON_OBJECT_KINDS
        for entry in document.values()
    )


def test_review_document_preserves_unknowns_reasons_and_profile_digest() -> None:
    document = review_document()
    profile = EXPERIMENTS_HARDWARE_PARTIAL_PROFILE
    profile_ids = {assignment.object_id for assignment in profile.assignments}
    assert sum(
        question["status"] == UNRESOLVED
        for entry in document.values()
        for question in entry["questions"].values()
    ) == 1418
    for object_id, entry in document.items():
        assert entry["expected_owned_path_set_digest"].startswith("sha256:")
        assert entry["expected_source_coordinate_digest"].startswith("sha256:")
        assert entry["scope_reason"].strip()
        assert all(
            question["reason"].strip()
            for question in entry["questions"].values()
        )
        assert entry["partial_profile_digest"] == (
            profile.canonical_digest if object_id in profile_ids else None
        )


def _rows_and_source_files() -> tuple[dict, dict]:
    """Build the minimal package rows and exact current source digests."""

    profile = EXPERIMENTS_HARDWARE_PARTIAL_PROFILE
    source = _source_map()
    rows: dict = {}
    files: dict = {}
    for assignment in profile.assignments:
        spec = source[assignment.object_id]
        rows[assignment.object_id] = {
            "object_id": assignment.object_id,
            "kind": spec.primary_kind,
            "surfaces": [f"file:{path}" for path in spec.owned_paths],
            "specializations": list(spec.specializations),
            "classification": {},
        }
        for path in spec.owned_paths:
            raw = (REPO_ROOT / path).read_bytes()
            files[path] = "sha256:" + sha256(raw).hexdigest()
    return rows, files


def test_profile_application_is_atomic_and_fails_closed() -> None:
    profile = EXPERIMENTS_HARDWARE_PARTIAL_PROFILE
    rows, files = _rows_and_source_files()

    applied = apply_original_kind_profile(REPO_ROOT, rows, files, profile)
    assert rows == _rows_and_source_files()[0]
    for assignment in profile.assignments:
        classification = applied[assignment.object_id]["classification"]
        assert {
            kind: entry["status"] for kind, entry in classification.items()
        } == {decision.kind: decision.status for decision in assignment.decisions}

    victim = profile.assignments[0].object_id
    stale_files = dict(files)
    stale_files[profile.assignments[0].expected_owned_paths[0]] = "sha256:" + "0" * 64
    before = deepcopy(rows)
    with pytest.raises(ValueError, match="SOURCE_DIFFERS:" + victim):
        apply_original_kind_profile(REPO_ROOT, rows, stale_files, profile)
    assert rows == before

    decided = profile.assignments[0].decisions[0]
    conflicting = deepcopy(rows)
    conflicting[victim]["classification"][decided.kind] = {
        "status": (
            DOES_NOT_APPLY if decided.status == APPLIES else APPLIES
        ),
        "reason": "prior conflicting claim",
        "evidence": [],
    }
    before = deepcopy(conflicting)
    with pytest.raises(ValueError, match="DECISION_CONFLICT:" + victim):
        apply_original_kind_profile(REPO_ROOT, conflicting, files, profile)
    assert conflicting == before

    substituted = deepcopy(rows)
    substituted[victim]["object_id"] = profile.assignments[1].object_id
    with pytest.raises(ValueError, match="OBJECT_MISSING:" + victim):
        apply_original_kind_profile(REPO_ROOT, substituted, files, profile)


# Behavior overlay: the checks below recompute every claim from disk with the
# same deterministic rules used to generate BEHAVIOR_OVERLAY. Keyword absence
# is a bounded refutation over the pinned evidence set, not a semantic proof.

_KIND_PREFIXES = {
    "ACTOR": ("actor", "principal", "delegat", "attribution", "accountab"),
    "AGENT": ("agent", "autonom", "trajector"),
    "ARCH": ("layer", "tensor", "architect", "transformer"),
    "BENCH": ("bench", "oracle", "scor", "budget"),
    "BOT": ("bot", "loop", "actuat", "controller"),
    "COLLECTIVE": ("collective", "quorum", "member"),
    "DATA": ("dataset", "partition", "lineage", "schema", "census", "corpus"),
    "ENV": ("environ", "depend", "reproduc", "runtime", "configur"),
    "EVENT": ("event", "occurr"),
    "GRAPH": ("graph", "vertex", "vertic", "edge"),
    "HARDWARE": (
        "device", "gpu", "accelerat", "cuda", "hardware", "topolog",
        "capacity", "substrate", "nvidia", "amd", "driver", "memory",
    ),
    "HARNESS": ("harness", "scaffold", "transcript", "tool", "channel", "instrument", "gap"),
    "HUMAN": ("human", "person", "living", "email"),
    "HYPER": ("hyper", "absorb", "ceiling", "operand", "cone"),
    "IDENTITY": ("identit", "bearer", "presentation"),
    "MODEL": ("model", "weight", "parameter", "checkpoint", "gguf", "lm", "llm"),
    "OWNER": ("owner", "ownership", "rights", "duty", "holder", "custod"),
    "RECEIPT": ("receipt", "replay"),
    "ROLE": ("role", "permission", "occupan", "authoriz", "authorit"),
    "SIM": ("simulat", "transition", "isolation", "sandbox"),
    "SPACE": ("spatial", "layout", "migrat", "network", "location"),
    "TIME": ("time", "clock", "epoch", "timestamp", "monotonic", "interval", "deadline", "timeout", "=perf"),
    "TOKEN": ("token", "lease", "tenure"),
    "TRAIN": ("train", "optimiz", "gradient", "batch"),
    "VERIFIER": ("verif", "checker", "verdict"),
}
_PHYSICAL = ("robot", "motor", "actuat", "servo", "gripper", "vehicle", "drone")
_MONETARY = ("payment", "invoice", "price", "money", "currency", "stripe", "billing", "monetar")
_LIVE_DEVICE_LITERALS = ("nvidia-smi", "rocm-smi", "amd-smi", "rocminfo", "nvidia-ml")
_SUBPROCESS_BLOCKING = ("run", "check_output", "check_call", "call")
_NORMALIZER_PREFIXES = ("decode", "normaliz", "canonical", "profile_digest", "references", "parse_", "encode")


def _prefix_match(word, prefixes):
    return any(
        word == prefix[1:] if prefix.startswith("=") else word.startswith(prefix)
        for prefix in prefixes
    )


def _is_local(module):
    return module.split(".")[0] == "verifier"


def _split(identifier):
    return [part.lower() for part in identifier.split("_") if part]


def _python_words_and_effects(text):
    tree = ast.parse(text)
    doc_ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                doc_ids.add(id(body[0].value))
    words = []
    effects = Counter()
    normalizers = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if not _is_local(alias.name):
                    words.extend(_split(alias.name))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level == 0 and not _is_local(module):
                words.extend(_split(module))
            for alias in node.names:
                words.extend(_split(alias.name))
            if node.level > 0 or _is_local(module):
                for alias in node.names:
                    if alias.name.startswith(_NORMALIZER_PREFIXES):
                        normalizers.append(module + ":" + alias.name)
        elif isinstance(node, ast.Name):
            words.extend(_split(node.id))
        elif isinstance(node, ast.Attribute):
            words.extend(_split(node.attr))
        elif isinstance(node, ast.arg):
            words.extend(_split(node.arg))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            words.extend(_split(node.name))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) in doc_ids:
                continue
            words.extend(re.findall(r"[a-z]+", node.value.lower()))
            if any(literal in node.value for literal in _LIVE_DEVICE_LITERALS):
                effects["live_device_literals"] += 1
        elif isinstance(node, ast.Call):
            func = node.func
            has_timeout = any(keyword.arg == "timeout" for keyword in node.keywords)
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "subprocess"
                and func.attr in _SUBPROCESS_BLOCKING
                and not has_timeout
            ):
                effects["unbounded_subprocess"] += 1
            if isinstance(func, ast.Attribute) and func.attr in {"wait", "communicate"}:
                if not node.args and not has_timeout:
                    effects["unbounded_wait"] += 1
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name == "urlopen" and not has_timeout and len(node.args) < 3:
                effects["unbounded_urlopen"] += 1
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in node.args.args + node.args.kwonlyargs:
                if arg.annotation is None:
                    continue
                annotation = ast.unparse(arg.annotation)
                if "Mapping" not in annotation and "Callable" not in annotation:
                    continue
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Subscript) and isinstance(inner.value, ast.Name) and inner.value.id == arg.arg:
                        effects["mapping_lookups"] += 1
                    if isinstance(inner, ast.Call):
                        target = inner.func
                        if isinstance(target, ast.Subscript):
                            target = target.value
                        if isinstance(target, ast.Name) and target.id == arg.arg:
                            effects["callback_invocations"] += 1
    return words, effects, normalizers


def _file_words(rel, text):
    if rel.endswith(".py"):
        return _python_words_and_effects(text)
    return re.findall(r"[a-z]+", text.lower()), Counter(), []


def _line_has_kind(line, kind):
    return any(
        _prefix_match(word, _KIND_PREFIXES[kind])
        for word in re.findall(r"[a-z]+", line.lower())
    )


def _direct_local_imports(path, text=None):
    src = REPO_ROOT / "src"
    tree = ast.parse(path.read_text(encoding="utf-8") if text is None else text)
    found = []

    def resolve(module, level):
        if level:
            base = path.parent
            for _ in range(level - 1):
                base = base.parent
            parts = module.split(".") if module else []
            candidates = [base.joinpath(*parts).with_suffix(".py"), base.joinpath(*parts, "__init__.py")]
        else:
            if module.split(".")[0] != "verifier":
                return []
            parts = module.split(".")
            candidates = [src.joinpath(*parts).with_suffix(".py"), src.joinpath(*parts, "__init__.py")]
        return [candidate for candidate in candidates if candidate.is_file()]

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            found.extend(resolve(node.module or "", node.level))
            for alias in node.names:
                joined = (node.module or "") + "." + alias.name if node.module else alias.name
                found.extend(resolve(joined, node.level))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                found.extend(resolve(alias.name, 0))
    return found


def _overlay_row(object_id):
    return next(row for row in EXPERIMENTS_HARDWARE_ORIGINAL_KIND_AUDITS if row.object_id == object_id)


def _evidence_files(object_id, helpers):
    row = _overlay_row(object_id)
    seed = [REPO_ROOT / path for path in row.expected_owned_paths] + [
        REPO_ROOT / path for path in helpers
    ]
    closure = set(seed)
    for path in list(seed):
        if path.suffix == ".py" and path.is_file():
            closure.update(_direct_local_imports(path))
    return sorted(
        {path.relative_to(REPO_ROOT).as_posix() for path in closure if path.is_file()}
    )


def _scan_object(object_id, entry, overrides=None):
    overrides = overrides or {}
    files = _evidence_files(object_id, entry["helpers"])
    entries = []
    opaque = []
    texts = {}
    words = []
    effects = Counter()
    normalizers = []
    for rel in files:
        raw = overrides.get(rel, (REPO_ROOT / rel).read_bytes())
        entries.append([rel, "sha256:" + sha256(raw).hexdigest()])
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            opaque.append(rel)
            continue
        texts[rel] = text
        file_words, file_effects, file_norm = _file_words(rel, text)
        words.extend(file_words)
        effects.update(file_effects)
        normalizers.extend(f"{rel}:{name}" for name in file_norm)
    digest = "sha256:" + sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    return {
        "files": files,
        "digest": digest,
        "opaque": opaque,
        "texts": texts,
        "counts": Counter(words),
        "effects": dict(sorted(effects.items())),
        "normalizers": tuple(normalizers),
        "physical": sum(count for word, count in Counter(words).items() if word.startswith(_PHYSICAL)),
        "monetary": sum(count for word, count in Counter(words).items() if word.startswith(_MONETARY)),
    }


def _kind_count(scan, kind):
    return sum(count for word, count in scan["counts"].items() if _prefix_match(word, _KIND_PREFIXES[kind]))


_SYNONYMS = {
    "ACTOR": ("operator", "principal", "approver", "decider", "signer", "reviewer", "user", "person"),
    "AGENT": ("assistant", "planner", "copilot", "autonom"),
    "ARCH": ("shape", "attention", "encoder", "tensor", "layer"),
    "BENCH": ("leaderboard", "suite", "trial", "scorer"),
    "BOT": ("robot", "automaton", "actuat", "controller", "loop"),
    "COLLECTIVE": ("group", "team", "committee", "vote", "consensus", "ballot", "quorum"),
    "DATA": ("table", "rows", "corpus", "dataset"),
    "ENV": ("host", "platform", "container", "docker", "machine", "venv", "environment"),
    "EVENT": ("incident", "occurrence", "happened"),
    "GRAPH": ("node", "adjacen", "dag", "hyperedge", "vertex", "edge"),
    "HARDWARE": ("cpu", "vram", "chip", "silicon", "accelerator", "gpu", "device"),
    "HARNESS": ("runner", "orchestrat", "executor", "scaffold", "transcript"),
    "HUMAN": ("people", "individual", "patient", "employee", "citizen", "person", "human"),
    "HYPER": ("composite", "absorb", "operand", "ceiling"),
    "IDENTITY": ("persona", "bearer", "presentation"),
    "MODEL": ("inference", "logit", "weights", "parameter", "checkpoint", "llm", "model"),
    "OWNER": ("custody", "steward", "possess", "holder", "owner"),
    "RECEIPT": ("receipt", "replay"),
    "ROLE": ("privilege", "permission", "authoriz", "authorit", "role"),
    "SIM": ("rollout", "generative", "transition", "simulat", "sandbox"),
    "SPACE": ("geometr", "address", "region", "coordinate", "layout", "location", "network"),
    "TIME": ("tick", "duration", "elapsed", "latency", "schedul", "clock", "timestamp", "timeout"),
    "TOKEN": ("credential", "hmac", "signature", "nonce", "lease", "tenure", "token"),
    "TRAIN": ("fit", "loss", "gradient", "optimiz", "batch", "train"),
    "VERIFIER": ("validat", "predicate", "checker", "verdict", "verif"),
}
_PROCESS_MODULES = frozenset({"subprocess", "os", "multiprocessing"})
_PROCESS_CALLS = frozenset({
    "Popen", "run", "call", "check_call", "check_output", "getoutput",
    "getstatusoutput", "system", "popen", "spawnl", "spawnv", "execv",
    "execvp", "fork", "Process",
})
_DEVICE_BLOCKS = frozenset({"ACTOR", "BOT", "HARDWARE", "ENV", "EVENT", "HARNESS"})
_PROCESS_BLOCKS = frozenset({"ACTOR", "AGENT", "BOT", "HARNESS", "HARDWARE", "ENV"})
_NETWORK_BLOCKS = _PROCESS_BLOCKS | {"SPACE"}
_CALLBACK_BLOCKS = frozenset({"ACTOR", "AGENT", "BOT", "HARNESS", "SIM"})
_EFFECT_BLOCKS = {
    "live_device_literals": _DEVICE_BLOCKS,
    "unbounded_subprocess": _PROCESS_BLOCKS,
    "unbounded_wait": _PROCESS_BLOCKS,
    "unbounded_urlopen": _NETWORK_BLOCKS,
    "callback_invocations": _CALLBACK_BLOCKS,
}


def _syn_hits(kind, text):
    low = text.lower()
    return sorted(
        {word for word in _SYNONYMS.get(kind, ()) if re.search(r"(?<![a-z])" + re.escape(word), low)}
    )


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return None if base is None else base + "." + node.attr
    return None


def _process_launches(text):
    """Count calls that launch a process, resolving import aliases."""

    tree = ast.parse(text)
    origins = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                origins[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                origins[alias.asname or alias.name] = node.module + "." + alias.name
    count = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _dotted(node.func)
        if dotted is None:
            continue
        head, _, rest = dotted.partition(".")
        full = origins.get(head, head) + ("." + rest if rest else "")
        if full.split(".")[0] in _PROCESS_MODULES and full.rsplit(".", 1)[-1] in _PROCESS_CALLS:
            count += 1
    return count


def _callback_invocations(text):
    """Count calls through a parameter, annotated or not (`cb(x)`, `table[k](x)`)."""

    tree = ast.parse(text)
    count = 0
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        args = node.args
        params = {arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
        params -= {"self", "cls"}  # `cls(...)` in a classmethod constructs; it is not a callback
        for inner in ast.walk(node):
            if isinstance(inner, ast.Call):
                target = inner.func
                while isinstance(target, ast.Subscript):
                    target = target.value
                if isinstance(target, ast.Name) and target.id in params:
                    count += 1
    return count


def _gate_codes(kinds, *, texts, stale=False, opaque=(), effects=None, processes=0, callbacks=0):
    """Return the mechanical blocker for each kind; kinds without a blocker are absent."""

    counts = Counter()
    for rel, text in texts.items():
        counts.update(_file_words(rel, text)[0])
    codes = {}
    for kind in kinds:
        hits = sum(count for word, count in counts.items() if _prefix_match(word, _KIND_PREFIXES[kind]))
        synonyms = sorted({word for text in texts.values() for word in _syn_hits(kind, text)})
        effect_names = [name for name in sorted(effects or {}) if kind in _EFFECT_BLOCKS.get(name, ())]
        if opaque:
            code = "OPAQUE_EVIDENCE:" + ",".join(sorted(opaque))
        elif stale:
            code = "STALE_SOURCE"
        elif hits:
            code = f"KEYWORD_HIT:{hits}"
        elif synonyms:
            code = "SYNONYM_HIT:" + ",".join(synonyms)
        elif processes and kind in _PROCESS_BLOCKS:
            code = f"PROCESS_LAUNCH:{processes}"
        elif callbacks and kind in _CALLBACK_BLOCKS:
            code = f"CALLBACK_INVOCATION:{callbacks}"
        elif effect_names:
            code = "EFFECT_CLOSURE:" + ",".join(effect_names)
        else:
            continue
        codes[kind] = code
    return codes


def _closure_texts(files, overrides):
    """Decode the transitive local import closure; undecodable files are opaque."""

    pending = [REPO_ROOT / rel for rel in files]
    seen = set(pending)
    texts, opaque = {}, []
    while pending:
        path = pending.pop()
        rel = path.relative_to(REPO_ROOT).as_posix()
        raw = overrides[rel] if rel in overrides else path.read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            opaque.append(rel)
            continue
        texts[rel] = text
        if path.suffix == ".py":
            for nxt in _direct_local_imports(path, text):
                if nxt not in seen:
                    seen.add(nxt)
                    pending.append(nxt)
    return texts, sorted(opaque)


def _dne_gate_codes(object_id, entry=None, overrides=None):
    """Return the mechanical blocker for every DNE kind the entry claims or downgrades."""

    entry = BEHAVIOR_OVERLAY[object_id] if entry is None else entry
    overrides = overrides or {}
    scan = _scan_object(object_id, entry, overrides)
    texts, opaque = _closure_texts(scan["files"], overrides)
    effects = Counter()
    processes = 0
    callbacks = 0
    for rel, text in texts.items():
        if rel.endswith(".py"):
            effects.update(_python_words_and_effects(text)[1])
            processes += _process_launches(text)
            callbacks += _callback_invocations(text)
    return _gate_codes(
        (*entry["dne"], *entry["blocked"]),
        texts=texts,
        stale=scan["digest"] != entry["digest"],
        opaque=opaque,
        effects=effects,
        processes=processes,
        callbacks=callbacks,
    )


def _retention_problems(object_id, entry):
    """A retained DNE must name a file of its own evidence set as its identity basis."""

    if not entry["dne"]:
        return []
    basis = entry.get("identity_basis", "")
    names = {path.rsplit("/", 1)[-1] for path in _evidence_files(object_id, entry["helpers"])}
    if not any(name in basis for name in names):
        return ["NO_IDENTITY_CITATION:" + object_id]
    return []


@lru_cache(maxsize=None)
def _cached_gate(object_id):
    """The live gate for the pinned entry, computed once per object per session."""

    return _dne_gate_codes(object_id)


def _verify_object(object_id, entry=None, overrides=None):
    """Return every recomputed-claim problem for one overlay object."""

    entry = BEHAVIOR_OVERLAY[object_id] if entry is None else entry
    row = _overlay_row(object_id)
    scan = _scan_object(object_id, entry, overrides)
    problems = []
    if not set(row.expected_owned_paths) <= set(scan["files"]):
        problems.append("OWNED_OUTSIDE_EVIDENCE:" + object_id)
    if scan["digest"] != entry["digest"]:
        problems.append("STALE_SOURCE:" + object_id)
    if len(scan["files"]) != entry["file_count"]:
        problems.append("FILE_COUNT_DRIFT:" + object_id)
    if scan["effects"] != entry["effects"]:
        problems.append("EFFECTS_DRIFT:" + object_id)
    if scan["physical"] != entry["physical_hits"] or scan["monetary"] != entry["monetary_hits"]:
        problems.append("PHYSICAL_OR_MONETARY_DRIFT:" + object_id)
    if scan["normalizers"] != entry["normalizers"]:
        problems.append("NORMALIZER_DRIFT:" + object_id)
    for kind, _reason, cites in entry["applies"]:
        supported = False
        for cite in cites:
            rel, span = cite.rsplit(":", 1)
            low, high = (int(part) for part in span.split("-"))
            if rel not in scan["texts"]:
                problems.append("CITE_OUTSIDE_EVIDENCE:" + object_id + ":" + kind)
                continue
            lines = scan["texts"][rel].splitlines()
            window = lines[max(low, 1) - 1 : min(high, len(lines))]
            supported = supported or any(_line_has_kind(line, kind) for line in window)
        if not supported:
            problems.append("UNSUPPORTED_APPLIES:" + object_id + ":" + kind)
    for kind, code in sorted(_dne_gate_codes(object_id, entry, overrides).items()):
        if kind in entry["dne"]:
            problems.append("DNE_GATE:" + object_id + ":" + kind + ":" + code)
    problems.extend(_retention_problems(object_id, entry))
    return problems


def test_overlay_totals_and_source_decisions_are_unchanged() -> None:
    assert set(BEHAVIOR_OVERLAY) == {
        row.object_id for row in EXPERIMENTS_HARDWARE_ORIGINAL_KIND_AUDITS
    }
    assert sum(len(entry["applies"]) for entry in BEHAVIOR_OVERLAY.values()) == OVERLAY_TOTALS["applies"] == 56
    retained = sum(len(entry["dne"]) for entry in BEHAVIOR_OVERLAY.values())
    downgraded = sum(len(entry["blocked"]) for entry in BEHAVIOR_OVERLAY.values())
    assert retained == OVERLAY_TOTALS["dne"]
    assert downgraded == OVERLAY_DOWNGRADE_TOTALS["dne"]
    assert retained + downgraded == PRIOR_OVERLAY_DNE_CLAIMS == 710
    assert EFFECTIVE_TOTALS == {
        "applies": 161,
        "dne": 27 + retained,
        "unresolved": 1418 - 56 - retained,
    }
    _overlay_check()

    effective = effective_review_document()
    document = review_document()
    counts = Counter()
    for row in EXPERIMENTS_HARDWARE_ORIGINAL_KIND_AUDITS:
        assert document[row.object_id]["behavior_overlay_digest"] == (
            BEHAVIOR_OVERLAY[row.object_id]["digest"]
        )
        for question in row.questions:
            status = effective[row.object_id][question.kind]
            counts[status] += 1
            if question.status != UNRESOLVED:
                assert status == question.status
    assert (counts["APPLIES"], counts["DOES_NOT_APPLY"], counts[UNRESOLVED]) == (
        EFFECTIVE_TOTALS["applies"],
        EFFECTIVE_TOTALS["dne"],
        EFFECTIVE_TOTALS["unresolved"],
    )


def test_every_overlay_claim_matches_recomputed_evidence() -> None:
    # The hardware adapter bytes have moved since the overlay digest was pinned.
    # That drift is classified, not repinned: the public-api overlay is stale and
    # its effects no longer match the pinned scan, so none of its claims survive.
    problems = {
        object_id: _verify_object(object_id)
        for object_id in BEHAVIOR_OVERLAY
    }
    assert {object_id: found for object_id, found in problems.items() if found} == {
        "vstd-hardware-public-api": [
            "STALE_SOURCE:vstd-hardware-public-api",
            "EFFECTS_DRIFT:vstd-hardware-public-api",
        ],
    }
    assert BEHAVIOR_OVERLAY["vstd-hardware-public-api"]["dne"] == ()


def test_stale_source_bytes_are_detected_and_real_bytes_pass() -> None:
    clean = "vstd-vgsat-package-marker"
    owned = _overlay_row(clean).expected_owned_paths[0]
    real = (REPO_ROOT / owned).read_bytes()
    assert _verify_object(clean) == []
    stale = _verify_object(clean, overrides={owned: real + b"\n# stale\n"})
    assert "STALE_SOURCE:" + clean in stale
    assert _verify_object(clean, overrides={owned: real}) == []
    # Every DNE on a stale object is blocked, so the drift cannot be papered over.
    gated = _dne_gate_codes(clean, overrides={owned: real + b"\n# stale\n"})
    claimed = set(BEHAVIOR_OVERLAY[clean]["dne"]) | set(BEHAVIOR_OVERLAY[clean]["blocked"])
    assert set(gated) == claimed
    assert set(gated.values()) == {"STALE_SOURCE"}


def test_wrong_object_entry_is_rejected_by_recomputed_digest() -> None:
    first, second = "vstd-vgsat-package-marker", "vstd-vgsat-vendored-license-policy"
    substituted = _verify_object(first, entry=BEHAVIOR_OVERLAY[second])
    assert "STALE_SOURCE:" + first in substituted
    assert _verify_object(first) == []
    assert _verify_object(second) == []


def test_live_device_probes_block_hardware_and_environment_exclusions() -> None:
    probe_objects = [
        object_id
        for object_id in BEHAVIOR_OVERLAY
        if _scan_object(object_id, BEHAVIOR_OVERLAY[object_id])["effects"].get("live_device_literals")
    ]
    assert probe_objects == ["vstd-hardware-public-api"]
    for object_id in probe_objects:
        dne = set(BEHAVIOR_OVERLAY[object_id]["dne"])
        assert "HARDWARE" not in dne
        assert "ENV" not in dne
    public = BEHAVIOR_OVERLAY["vstd-hardware-public-api"]["effects"]
    assert public["live_device_literals"] == 10
    assert public["unbounded_subprocess"] == 2

    words, effects, _norm = _python_words_and_effects(
        "import subprocess\nsubprocess.run(['nvidia-smi', '--query-gpu=uuid'], capture_output=True)\n"
    )
    assert effects["unbounded_subprocess"] == 1
    assert effects["live_device_literals"] == 1
    _words, bounded, _norm = _python_words_and_effects(
        "import subprocess\nsubprocess.run(['nvidia-smi'], capture_output=True, timeout=5)\n"
    )
    assert bounded.get("unbounded_subprocess", 0) == 0


def test_subprocess_wait_and_urlopen_bounds_are_classified() -> None:
    _w, unbounded_wait, _n = _python_words_and_effects("proc.wait()\nproc.communicate()\n")
    assert unbounded_wait["unbounded_wait"] == 2
    _w, bounded_wait, _n = _python_words_and_effects("proc.wait(timeout=1.0)\nproc.communicate(timeout=1)\n")
    assert bounded_wait.get("unbounded_wait", 0) == 0
    _w, spawn, _n = _python_words_and_effects(
        "import subprocess\nchild = subprocess.Popen(['x'])\n"
    )
    # The pinned scan is a historical blind spot for Popen; the DNE gate counts it.
    assert spawn.get("unbounded_subprocess", 0) == 0
    assert _process_launches("import subprocess\nchild = subprocess.Popen(['x'])\n") == 1
    _w, net, _n = _python_words_and_effects("urlopen(request)\n")
    assert net["unbounded_urlopen"] == 1
    _w, bounded_net, _n = _python_words_and_effects("urlopen(request, timeout=180)\n")
    assert bounded_net.get("unbounded_urlopen", 0) == 0


def test_callback_invocations_are_distinct_from_mapping_lookups() -> None:
    _w, invoked, _n = _python_words_and_effects(
        "from typing import Callable\n"
        "def f(cb: Callable[[str], str]) -> str:\n"
        "    return cb('x')\n"
    )
    assert invoked["callback_invocations"] == 1
    _w, looked_up, _n = _python_words_and_effects(
        "from typing import Mapping\n"
        "def g(table: Mapping[str, str], key: str) -> str:\n"
        "    return table[key]\n"
    )
    assert looked_up["mapping_lookups"] == 1
    assert looked_up.get("callback_invocations", 0) == 0
    _w, subscript_call, _n = _python_words_and_effects(
        "from typing import Callable, Mapping\n"
        "def h(fns: Mapping[str, Callable[[], int]], key: str) -> int:\n"
        "    return fns[key]()\n"
    )
    assert subscript_call["callback_invocations"] == 1
    assert all(
        "callback_invocations" not in entry["effects"] for entry in BEHAVIOR_OVERLAY.values()
    )


def test_imported_normalizers_are_recorded_for_common_mode_premises() -> None:
    _w, _e, imported = _python_words_and_effects(
        "from verifier.interoperability.formation_wire import decode_subject\n"
    )
    assert imported == ["verifier.interoperability.formation_wire:decode_subject"]
    for object_id in (
        "vstd-typed-formation-certificate-producer",
        "vstd-typed-formation-checker",
    ):
        recorded = BEHAVIOR_OVERLAY[object_id]["normalizers"]
        assert any(
            "formation_wire" in entry
            and entry.rsplit(":", 1)[1].startswith(("decode", "references", "profile_digest"))
            for entry in recorded
        ), object_id


def test_physical_endpoints_and_monetary_effects_have_zero_hits() -> None:
    assert all(
        entry["physical_hits"] == 0 and entry["monetary_hits"] == 0
        for entry in BEHAVIOR_OVERLAY.values()
    )
    counts = Counter(_python_words_and_effects("motor_torque = 3\n")[0])
    assert sum(count for word, count in counts.items() if word.startswith(_PHYSICAL)) == 1
    counts = Counter(_python_words_and_effects("payment_amount = 1\n")[0])
    assert sum(count for word, count in counts.items() if word.startswith(_MONETARY)) == 1
    prose = Counter(re.findall(r"[a-z]+", "an accounting ledger of previous roots".lower()))
    assert sum(count for word, count in prose.items() if word.startswith(_MONETARY)) == 0


def test_overlay_validation_is_all_or_nothing_and_fail_closed() -> None:
    victim = next(
        row.object_id
        for row in EXPERIMENTS_HARDWARE_ORIGINAL_KIND_AUDITS
        if any(question.status == DOES_NOT_APPLY for question in row.questions)
    )
    source_dne = next(
        question.kind
        for question in _overlay_row(victim).questions
        if question.status == DOES_NOT_APPLY
    )
    bad = deepcopy(BEHAVIOR_OVERLAY)
    bad[victim]["dne"] = bad[victim]["dne"] + (source_dne,)
    before = deepcopy(BEHAVIOR_OVERLAY)
    with pytest.raises(AssertionError, match="overlay"):
        _overlay_check(bad)
    with pytest.raises(AssertionError, match="overlay"):
        effective_review_document(bad)
    assert BEHAVIOR_OVERLAY == before

    short = deepcopy(BEHAVIOR_OVERLAY)
    short["vstd-vgsat-package-marker"]["dne"] = short["vstd-vgsat-package-marker"]["dne"][:-1]
    with pytest.raises(AssertionError, match="denominator differs"):
        effective_review_document(short)


def test_every_downgraded_dne_has_an_exact_blocker_and_no_retained_gate_hit() -> None:
    audits = {row.object_id: row for row in EXPERIMENTS_HARDWARE_ORIGINAL_KIND_AUDITS}
    for object_id, entry in BEHAVIOR_OVERLAY.items():
        retained = set(entry["dne"])
        blocked = entry["blocked"]
        assert retained.isdisjoint(blocked), object_id
        assert all(isinstance(code, str) and code.strip() for code in blocked.values())
        unresolved = {
            question.kind
            for question in audits[object_id].questions
            if question.status == UNRESOLVED
        }
        assert set(blocked) <= unresolved and retained <= unresolved, object_id
        assert _retention_problems(object_id, entry) == []
        gate = _cached_gate(object_id)
        assert retained.isdisjoint(gate), object_id
        for kind, code in gate.items():
            if kind in blocked:
                assert blocked[kind] == code, (object_id, kind)


def test_retained_dne_cells_have_positive_identity_and_zero_gate_hits() -> None:
    for object_id, entry in BEHAVIOR_OVERLAY.items():
        if not entry["dne"]:
            continue
        assert _retention_problems(object_id, entry) == [], object_id
        assert set(_cached_gate(object_id)).isdisjoint(entry["dne"]), object_id


# The one-hop digest pins only the evidence set. Blocker counts also read the
# transitive import closure, so objects whose blockers depend on that closure
# carry a content pin over the whole closure. Count-only gates cannot see a
# same-count substitution; the content pin can.

_CLOSURE_PINNED = (
    "vstd-graph-topology-verifier",
    "vstd-untraversability-verifier",
)


def _closure_pin(object_id, overrides=None):
    """Return the digest and file count of the full transitive import closure."""

    overrides = overrides or {}
    seed = _evidence_files(object_id, BEHAVIOR_OVERLAY[object_id]["helpers"])
    texts, opaque = _closure_texts(seed, overrides)
    rels = sorted(set(texts) | set(opaque))
    entries = [
        [rel, "sha256:" + sha256(overrides[rel] if rel in overrides else (REPO_ROOT / rel).read_bytes()).hexdigest()]
        for rel in rels
    ]
    digest = "sha256:" + sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    return digest, len(rels)


def test_closure_pins_bind_transitive_blocker_evidence_exactly() -> None:
    for object_id in _CLOSURE_PINNED:
        entry = BEHAVIOR_OVERLAY[object_id]
        assert _closure_pin(object_id) == (
            entry["closure_digest"],
            entry["closure_file_count"],
        ), object_id
        assert entry["closure_hit_disposition"].strip(), object_id


def test_same_count_closure_substitution_passes_count_gate_and_fails_content_pin() -> None:
    object_id = "vstd-graph-topology-verifier"
    rel = "src/verifier/data/policy.py"
    real = (REPO_ROOT / rel).read_bytes()
    # `member_values` -> `member_xalues` keeps the COLLECTIVE prefix count and changes the bytes.
    swapped = real.replace(b"member_values", b"member_xalues")
    assert swapped != real
    gated = _dne_gate_codes(object_id, overrides={rel: swapped})
    assert gated["COLLECTIVE"] == BEHAVIOR_OVERLAY[object_id]["blocked"]["COLLECTIVE"]
    assert _closure_pin(object_id, overrides={rel: swapped})[0] != (
        BEHAVIOR_OVERLAY[object_id]["closure_digest"]
    )


def test_behaviorally_meaningful_closure_hit_fails_the_pinned_blocker() -> None:
    object_id = "vstd-graph-topology-verifier"
    rel = "src/verifier/data/policy.py"
    grown = (REPO_ROOT / rel).read_bytes() + b"\nQUORUM_SIGNOFF = 1\n"
    gated = _dne_gate_codes(object_id, overrides={rel: grown})
    assert gated["COLLECTIVE"] == "KEYWORD_HIT:86"
    assert gated["COLLECTIVE"] != BEHAVIOR_OVERLAY[object_id]["blocked"]["COLLECTIVE"]
    assert _closure_pin(object_id, overrides={rel: grown})[0] != (
        BEHAVIOR_OVERLAY[object_id]["closure_digest"]
    )


# Adversarial checks: each gate is exercised on synthetic evidence so that a
# zero-hit, synonym, import, callback, opacity or referent mistake fails here.


def test_zero_keyword_hits_alone_do_not_grant_a_dne() -> None:
    texts = {"x.py": "def f(a):\n    return a + 1\n"}
    assert _gate_codes(["ACTOR"], texts=texts) == {}
    clean = "vstd-vgsat-package-marker"
    helpers = BEHAVIOR_OVERLAY[clean]["helpers"]
    # Zero hits pass the mechanical gate, but without a named identity file the DNE is refused.
    assert _retention_problems(clean, {"dne": ("ACTOR",), "identity_basis": "", "helpers": helpers}) == [
        "NO_IDENTITY_CITATION:" + clean
    ]
    assert _retention_problems(
        clean,
        {"dne": ("ACTOR",), "identity_basis": "catalog-like marker, no effects", "helpers": helpers},
    ) == ["NO_IDENTITY_CITATION:" + clean]
    assert _retention_problems(
        clean,
        {"dne": ("ACTOR",), "identity_basis": "__init__.py: inert marker, no effects", "helpers": helpers},
    ) == []


def test_synonym_hit_blocks_a_zero_keyword_dne() -> None:
    texts = {"notes.md": "The operator approves each run before it starts.\n"}
    assert _gate_codes(["ACTOR"], texts=texts) == {"ACTOR": "SYNONYM_HIT:operator"}


def test_referent_mention_blocks_rather_than_grants_a_dne() -> None:
    texts = {"catalog.json": '{"devices": ["gpu-0"], "reviewer": "a person signs off"}'}
    codes = _gate_codes(["HARDWARE", "HUMAN"], texts=texts)
    assert codes["HARDWARE"].startswith("KEYWORD_HIT:")
    assert codes["HUMAN"].startswith("KEYWORD_HIT:")


def test_aliased_process_launch_is_counted_by_the_gate() -> None:
    assert _process_launches("from subprocess import Popen as P\nP(['x'])\n") == 1
    assert _process_launches("import subprocess as sp\nsp.run(['x'])\n") == 1
    assert _process_launches("import os\nos.system('x')\n") == 1
    assert _process_launches("import os\nos.path.join('a', 'b')\n") == 0
    codes = _gate_codes(["ACTOR", "BOT", "SIM"], texts={"a.py": "x = 1\n"}, processes=1)
    assert codes == {
        "ACTOR": "PROCESS_LAUNCH:1",
        "BOT": "PROCESS_LAUNCH:1",
    }


def test_unannotated_callback_invocation_is_blocked_but_mapping_lookup_is_not() -> None:
    assert _callback_invocations("def run(step):\n    return step(1)\n") == 1
    assert _callback_invocations("def run(table):\n    return table['x']()\n") == 1
    assert _callback_invocations("def g(table, key):\n    return table[key]\n") == 0
    assert _callback_invocations(
        "class C:\n    @classmethod\n    def make(cls, x):\n        return cls(x)\n"
    ) == 0
    codes = _gate_codes(["AGENT", "SIM", "HUMAN"], texts={"a.py": "x = 1\n"}, callbacks=1)
    assert codes == {"AGENT": "CALLBACK_INVOCATION:1", "SIM": "CALLBACK_INVOCATION:1"}


def test_binary_opacity_blocks_every_dne_kind() -> None:
    assert _gate_codes(["HUMAN", "OWNER"], texts={}, opaque=("bin/x.dat",)) == {
        "HUMAN": "OPAQUE_EVIDENCE:bin/x.dat",
        "OWNER": "OPAQUE_EVIDENCE:bin/x.dat",
    }
    clean = "vstd-vgsat-package-marker"
    owned = _overlay_row(clean).expected_owned_paths[0]
    gated = _dne_gate_codes(clean, overrides={owned: b"\xff\xfe\x00bad"})
    claimed = set(BEHAVIOR_OVERLAY[clean]["dne"]) | set(BEHAVIOR_OVERLAY[clean]["blocked"])
    assert set(gated) == claimed
    assert set(gated.values()) == {"OPAQUE_EVIDENCE:" + owned}


def test_pinned_one_hop_scan_does_not_hide_transitive_process_launch() -> None:
    # A transitive helper's launch must reach the gate even when the owned file is clean.
    texts = {
        "owned.py": "from helper import run\nrun()\n",
        "helper.py": "import subprocess\nsubprocess.Popen(['x'])\n",
    }
    processes = sum(_process_launches(text) for text in texts.values())
    assert _gate_codes(["ACTOR", "AGENT", "EVENT"], texts=texts, processes=processes) == {
        "ACTOR": "PROCESS_LAUNCH:1",
        "AGENT": "PROCESS_LAUNCH:1",
    }

