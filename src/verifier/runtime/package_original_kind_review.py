"""Apply explicit original-kind reviews to current source-owned package rows.

Terminology: abstract syntax tree (AST).

Every emitted decision comes from a named profile assignment.  Existing
manifest bytes are checked for contradiction but never used to invent a role or
an exclusion.  Primary labels, caller-supplied source review, and consequence
closure can only add required ``APPLIES`` constraints; none can be refuted by a
profile.  Opening, pre-copy closing, and return-time source snapshots prevent a
decision from straddling a concurrent source edit.
"""

from __future__ import annotations

import ast
import collections
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from pathlib import PurePosixPath
import sys
from typing import Any, Iterable, Mapping

from verifier.runtime.package_original_kind_profiles import (
    APPLIES,
    DOES_NOT_APPLY,
    ORIGINAL_NON_OBJECT_KINDS,
    OriginalKindAssignment,
    OriginalKindProfile,
    VERIFIER_PACKAGE_OBJECT_DENOMINATOR,
    validate_full_closure,
    validate_profile,
)


def _bytes_digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _owned_file_paths(row: Mapping[str, Any], *, object_id: str) -> set[str]:
    surfaces = row.get("surfaces")
    if type(surfaces) is not list or any(type(item) is not str for item in surfaces):
        raise ValueError("PACKAGE_ORIGINAL_KIND_REVIEW_SURFACES_INVALID:" + object_id)
    return {
        item.removeprefix("file:")
        for item in surfaces
        if item.startswith("file:")
    }


def _source_snapshot(
    root: Path,
    assignment: OriginalKindAssignment,
) -> tuple[dict[str, str], ...]:
    evidence: list[dict[str, str]] = []
    for path in assignment.expected_owned_paths:
        try:
            target = (root / path).resolve(strict=True)
            target.relative_to(root)
            if not target.is_file():
                raise ValueError(path)
            digest = _bytes_digest(target.read_bytes())
        except (OSError, ValueError) as exc:
            raise ValueError(
                "PACKAGE_ORIGINAL_KIND_REVIEW_SOURCE_UNAVAILABLE:"
                + assignment.object_id
                + ":"
                + path
            ) from exc
        evidence.append({"path": path, "sha256": digest})
    return tuple(evidence)


def _validated_requirement_map(
    value: Mapping[str, Iterable[str]] | None,
    assignments: Mapping[str, OriginalKindAssignment],
    *,
    label: str,
) -> dict[str, frozenset[str]]:
    if value is None:
        return {}
    if type(value) is not dict:
        raise ValueError("PACKAGE_ORIGINAL_KIND_REVIEW_" + label + "_INVALID")
    result: dict[str, frozenset[str]] = {}
    for object_id, kinds in value.items():
        if type(object_id) is not str or object_id not in assignments:
            raise ValueError(
                "PACKAGE_ORIGINAL_KIND_REVIEW_" + label + "_OBJECT_INVALID"
            )
        try:
            selected = tuple(kinds)
        except TypeError as exc:
            raise ValueError(
                "PACKAGE_ORIGINAL_KIND_REVIEW_" + label + "_KINDS_INVALID:"
                + object_id
            ) from exc
        if (
            any(type(kind) is not str for kind in selected)
            or len(selected) != len(set(selected))
            or any(kind not in ORIGINAL_NON_OBJECT_KINDS for kind in selected)
        ):
            raise ValueError(
                "PACKAGE_ORIGINAL_KIND_REVIEW_" + label + "_KINDS_INVALID:"
                + object_id
            )
        result[object_id] = frozenset(selected)
    return result


def _existing_status(decision: Any, *, object_id: str, kind: str) -> str | None:
    if decision is None:
        return None
    if type(decision) is not dict or set(decision) != {"status", "reason", "evidence"}:
        raise ValueError(
            "PACKAGE_ORIGINAL_KIND_REVIEW_EXISTING_DECISION_INVALID:"
            + object_id
            + ":"
            + kind
        )
    status = decision["status"]
    if status not in {"UNRESOLVED", APPLIES, DOES_NOT_APPLY}:
        raise ValueError(
            "PACKAGE_ORIGINAL_KIND_REVIEW_EXISTING_STATUS_INVALID:"
            + object_id
            + ":"
            + kind
        )
    if type(decision["reason"]) is not str or type(decision["evidence"]) is not list:
        raise ValueError(
            "PACKAGE_ORIGINAL_KIND_REVIEW_EXISTING_DECISION_INVALID:"
            + object_id
            + ":"
            + kind
        )
    return status


def apply_original_kind_profile(
    root: str | Path,
    rows: Mapping[str, dict[str, Any]],
    files: Mapping[str, str],
    profile: OriginalKindProfile,
    *,
    source_applies: Mapping[str, Iterable[str]] | None = None,
    consequence_applies: Mapping[str, Iterable[str]] | None = None,
    require_full_closure: bool = False,
    expected_object_ids: Iterable[str] | None = None,
    expected_object_count: int = VERIFIER_PACKAGE_OBJECT_DENOMINATOR,
    unestablished_primary: str = "refuse",
    unreviewed_paths: str = "refuse",
    superseded_refutations: str = "refuse",
    documented_retention_keys: frozenset[tuple[str, str]] = frozenset(),
) -> dict[str, dict[str, Any]]:
    """Apply only literal profile decisions and reject every known conflict.

    ``source_applies`` and ``consequence_applies`` are independent audited
    constraints supplied by their owning mechanisms.  They validate this
    profile; they are never copied into it or used to fill a missing decision.

    A declared primary kind needs a decision.  ``unestablished_primary="refuse"``
    (the maintainer default) rejects the whole application when the profile has
    none.  ``"record"`` keeps that one cell UNRESOLVED with a reason naming the
    gap, so a receipt can still be produced and the object's verdict stays
    UNKNOWN.  It forgives nothing else: a kind demanded by source or consequence
    evidence, and any refutation of the primary, still reject the application.

    ``unreviewed_paths="refuse"`` (the maintainer default) rejects an object that
    owns any path the profile did not review.  ``"record"`` accepts an object whose
    owned set is a strict superset of the reviewed set, so a file added after the
    review no longer stops the receipt.  The unreviewed paths speak for nothing: an
    APPLIES finding keeps its cited evidence, because extra files cannot weaken it,
    while a DOES_NOT_APPLY refutation is a closed-world claim over the reviewed set
    and reopens as UNRESOLVED.  A reviewed path that is missing still rejects.

    ``superseded_refutations="refuse"`` (the maintainer default) rejects any prior
    APPLIES/DOES_NOT_APPLY cell that disagrees with a profile decision.  ``"record"``
    lets a profile's cited APPLIES replace a prior DOES_NOT_APPLY: that only adds
    obligations, and the old reason is kept in the new cell for audit.  The reverse
    remains forbidden unless the exact object/kind is in
    ``documented_retention_keys``; such a key means checked reasons.vstd APPLIES
    keeps the obligations in force while the source-only decision is restored.
    """
    if unestablished_primary not in {"refuse", "record"}:
        raise ValueError("PACKAGE_ORIGINAL_KIND_REVIEW_PRIMARY_POLICY_INVALID")
    if unreviewed_paths not in {"refuse", "record"}:
        raise ValueError("PACKAGE_ORIGINAL_KIND_REVIEW_UNREVIEWED_POLICY_INVALID")
    if superseded_refutations not in {"refuse", "record"}:
        raise ValueError("PACKAGE_ORIGINAL_KIND_REVIEW_SUPERSEDE_POLICY_INVALID")
    if type(documented_retention_keys) is not frozenset or any(
        type(key) is not tuple
        or len(key) != 2
        or type(key[0]) is not str
        or type(key[1]) is not str
        or key[1] not in ORIGINAL_NON_OBJECT_KINDS
        for key in documented_retention_keys
    ):
        raise ValueError(
            "PACKAGE_ORIGINAL_KIND_REVIEW_DOCUMENTED_RETENTION_INVALID"
        )
    selected_root = Path(root).resolve(strict=True)
    selected = validate_profile(profile)
    expected = None if expected_object_ids is None else tuple(expected_object_ids)
    if require_full_closure:
        if expected is None:
            raise ValueError(
                "PACKAGE_ORIGINAL_KIND_REVIEW_EXPECTED_OBJECTS_REQUIRED"
            )
        validate_full_closure(
            selected,
            expected,
            expected_object_count=expected_object_count,
        )
    elif expected is not None:
        raise ValueError("PACKAGE_ORIGINAL_KIND_REVIEW_UNUSED_EXPECTED_OBJECTS")
    if type(rows) is not dict:
        raise ValueError("PACKAGE_ORIGINAL_KIND_REVIEW_ROWS_INVALID")
    if require_full_closure and set(rows) != set(expected or ()):
        raise ValueError("PACKAGE_ORIGINAL_KIND_REVIEW_ROW_DENOMINATOR_DIFFERS")
    if type(files) is not dict or any(
        type(path) is not str or type(digest) is not str
        for path, digest in files.items()
    ):
        raise ValueError("PACKAGE_ORIGINAL_KIND_REVIEW_FILES_INVALID")

    assignments = {row.object_id: row for row in selected.assignments}
    source = _validated_requirement_map(
        source_applies, assignments, label="SOURCE_APPLIES"
    )
    consequences = _validated_requirement_map(
        consequence_applies, assignments, label="CONSEQUENCE_APPLIES"
    )
    plans: dict[str, dict[str, Any]] = {}
    for object_id, assignment in assignments.items():
        row = rows.get(object_id)
        if type(row) is not dict or row.get("object_id") != object_id:
            raise ValueError("PACKAGE_ORIGINAL_KIND_REVIEW_OBJECT_MISSING:" + object_id)
        if row.get("kind") != assignment.expected_primary:
            raise ValueError(
                "PACKAGE_ORIGINAL_KIND_REVIEW_PRIMARY_DIFFERS:" + object_id
            )
        owned = _owned_file_paths(row, object_id=object_id)
        reviewed = set(assignment.expected_owned_paths)
        if owned != reviewed and not (
            unreviewed_paths == "record" and reviewed < owned
        ):
            raise ValueError(
                "PACKAGE_ORIGINAL_KIND_REVIEW_OWNERSHIP_DIFFERS:" + object_id
            )
        unreviewed = sorted(owned - reviewed)
        opening = _source_snapshot(selected_root, assignment)
        for reference in opening:
            if files.get(reference["path"]) != reference["sha256"]:
                raise ValueError(
                    "PACKAGE_ORIGINAL_KIND_REVIEW_SOURCE_DIFFERS:"
                    + object_id
                    + ":"
                    + reference["path"]
                )
        classification = row.get("classification")
        if type(classification) is not dict:
            raise ValueError(
                "PACKAGE_ORIGINAL_KIND_REVIEW_CLASSIFICATION_INVALID:"
                + object_id
            )
        specializations = row.get("specializations")
        if type(specializations) is not list or any(
            type(kind) is not str for kind in specializations
        ):
            raise ValueError(
                "PACKAGE_ORIGINAL_KIND_REVIEW_SPECIALIZATIONS_INVALID:"
                + object_id
            )
        decisions = {decision.kind: decision for decision in assignment.decisions}
        required = set(source.get(object_id, ())) | set(
            consequences.get(object_id, ())
        )
        if assignment.expected_primary in ORIGINAL_NON_OBJECT_KINDS:
            required.add(assignment.expected_primary)
        required.update(
            kind for kind in specializations if kind in ORIGINAL_NON_OBJECT_KINDS
        )
        missing_required = required - set(decisions)
        unestablished: set[str] = set()
        if unestablished_primary == "record" and missing_required:
            # Only the declared primary label may be recorded as a gap, and only when
            # no source or consequence authority demands it.
            primary = assignment.expected_primary
            demanded = set(source.get(object_id, ())) | set(
                consequences.get(object_id, ())
            )
            if (
                primary in ORIGINAL_NON_OBJECT_KINDS
                and primary in missing_required
                and primary not in demanded
            ):
                unestablished.add(primary)
                missing_required = missing_required - unestablished
        if missing_required:
            raise ValueError(
                "PACKAGE_ORIGINAL_KIND_REVIEW_REQUIRED_UNDECIDED:"
                + object_id
                + ":"
                + ",".join(sorted(missing_required))
            )
        superseded: dict[str, str] = {}
        retained_prior_applies: set[str] = set()
        for kind, decision in decisions.items():
            if decision.status == DOES_NOT_APPLY and kind in required:
                raise ValueError(
                    "PACKAGE_ORIGINAL_KIND_REVIEW_REQUIRED_REFUTED:"
                    + object_id
                    + ":"
                    + kind
                )
            prior = _existing_status(
                classification.get(kind), object_id=object_id, kind=kind
            )
            if prior in {APPLIES, DOES_NOT_APPLY} and prior != decision.status:
                superseded_refutation = (
                    superseded_refutations == "record"
                    and prior == DOES_NOT_APPLY
                    and decision.status == APPLIES
                )
                retained_source_reversal = (
                    superseded_refutations == "record"
                    and prior == APPLIES
                    and decision.status == DOES_NOT_APPLY
                    and (object_id, kind) in documented_retention_keys
                )
                if not (superseded_refutation or retained_source_reversal):
                    raise ValueError(
                        "PACKAGE_ORIGINAL_KIND_REVIEW_DECISION_CONFLICT:"
                        + object_id
                        + ":"
                        + kind
                    )
                if superseded_refutation:
                    old_reason = classification[kind].get("reason")
                    superseded[kind] = (
                        old_reason if type(old_reason) is str else ""
                    )
                else:
                    retained_prior_applies.add(kind)
        # An affirmative prior outside this partition is a known source claim,
        # not permission for a partial profile to ignore the question.
        for kind in ORIGINAL_NON_OBJECT_KINDS:
            prior = _existing_status(
                classification.get(kind), object_id=object_id, kind=kind
            )
            if prior == APPLIES and kind not in decisions and kind not in unestablished:
                raise ValueError(
                    "PACKAGE_ORIGINAL_KIND_REVIEW_PRIOR_APPLIES_UNDECIDED:"
                    + object_id
                    + ":"
                    + kind
                )
        plans[object_id] = {
            "assignment": assignment,
            "opening": opening,
            "unestablished": sorted(unestablished),
            "unreviewed": unreviewed,
            "superseded": superseded,
            "retained_prior_applies": retained_prior_applies,
        }

    # Source truth is sampled again after every semantic conflict check.
    for object_id, plan in plans.items():
        if _source_snapshot(selected_root, plan["assignment"]) != plan["opening"]:
            raise ValueError(
                "PACKAGE_ORIGINAL_KIND_REVIEW_SOURCE_CHANGED:" + object_id
            )

    result = deepcopy(rows)
    for object_id, plan in plans.items():
        assignment = plan["assignment"]
        evidence = [dict(reference) for reference in plan["opening"]]
        unreviewed = plan["unreviewed"]
        for decision in assignment.decisions:
            selected_paths = set(decision.evidence_paths)
            decision_evidence = (
                [
                    dict(reference)
                    for reference in plan["opening"]
                    if reference["path"] in selected_paths
                ]
                if selected_paths
                else deepcopy(evidence)
            )
            reason = (
                "Audited original-kind profile "
                + selected.profile_id
                + " revision "
                + str(selected.revision)
                + " ("
                + selected.canonical_digest
                + ") binds this object and exact owned source set. "
                + assignment.scope_reason
                + " "
                + decision.reason
            )
            if unreviewed and decision.status == DOES_NOT_APPLY:
                result[object_id]["classification"][decision.kind] = {
                    "status": "UNRESOLVED",
                    "reason": _reopened_refutation(unreviewed, reason),
                    "evidence": [],
                }
                continue
            if unreviewed:
                reason += _unreviewed_note(unreviewed)
            if decision.kind in plan["superseded"]:
                reason += (
                    " Superseded refutation (kept for audit): "
                    + plan["superseded"][decision.kind]
                )
            if decision.kind in plan["retained_prior_applies"]:
                reason += (
                    " The prior source APPLIES decision is not erased from the "
                    "obligation denominator: checked reasons.vstd APPLIES retains "
                    "this kind while this cell records only the source review."
                )
            result[object_id]["classification"][decision.kind] = {
                "status": decision.status,
                "reason": reason,
                "evidence": decision_evidence,
            }
        for kind in plan["unestablished"]:
            gap = (
                "Unestablished primary label: audited original-kind profile "
                + selected.profile_id
                + " revision "
                + str(selected.revision)
                + " records no decision for "
                + kind
                + ", the declared primary kind of this object. A primary label "
                "is not evidence and a profile cannot refute it"
            )
            cell = result[object_id]["classification"][kind]
            if _existing_status(cell, object_id=object_id, kind=kind) == APPLIES:
                # The direct role declaration stands, so the kind's obligations stay in
                # force.  Only its source support is recorded as missing.
                cell["reason"] = (
                    cell["reason"]
                    + " "
                    + gap
                    + ", so the declaration is not yet supported by owned source."
                )
            else:
                result[object_id]["classification"][kind] = {
                    "status": "UNRESOLVED",
                    "reason": gap
                    + ", so this cell stays UNRESOLVED until owned source evidence "
                    "is cited or the label is corrected.",
                    "evidence": [],
                }

    # Copy construction can take time; do not return a stale source binding.
    for object_id, plan in plans.items():
        if _source_snapshot(selected_root, plan["assignment"]) != plan["opening"]:
            raise ValueError(
                "PACKAGE_ORIGINAL_KIND_REVIEW_SOURCE_CHANGED:" + object_id
            )
    return result


def _unreviewed_note(paths: list[str]) -> str:
    """Name how many owned paths lie outside a decision's reviewed source set."""
    plural = "" if len(paths) == 1 else "s"
    return (
        " This decision speaks only to the reviewed source set; "
        + str(len(paths))
        + " unreviewed owned path"
        + plural
        + " joined after the review."
    )


def _reopened_refutation(paths: list[str], reviewed_reason: str) -> str:
    """Explain why a closed-world refutation no longer covers the owned set."""
    shown = ", ".join(paths[:3]) + (", ..." if len(paths) > 3 else "")
    return (
        "Reopened: a refutation is a closed claim over the reviewed source set, and "
        + str(len(paths))
        + " unreviewed owned path"
        + ("" if len(paths) == 1 else "s")
        + " ("
        + shown
        + ") joined after that review, so absence there is unknown, not refuted. "
        "Prior reviewed reason: " + reviewed_reason
    )


_EFFECT_AUDIT_SCHEMA = "verifier-source-closed-effect-audit-1"
_EFFECT_CHANNELS = frozenset({
    "filesystem_read",
    "filesystem_write",
    "subprocess_process",
    "network",
    "environment",
    "clock",
    "randomness",
    "callback_injected_callable",
    "dynamic_import_eval_exec_reflection",
    "hardware_device",
    "serialization_message_boundary",
})
_DYNAMIC_OPERATIONS = frozenset({
    "__import__", "compile", "delattr", "dir", "eval", "exec", "getattr",
    "globals", "hasattr", "importlib.import_module", "locals", "setattr", "vars",
})
_PURE_BUILTINS = frozenset({
    "abs", "all", "any", "ascii", "bin", "bool", "bytearray", "bytes",
    "callable", "chr", "complex", "dict", "divmod", "enumerate", "filter",
    "float", "format", "frozenset", "hash", "hex", "int", "isinstance",
    "issubclass", "iter", "len", "list", "map", "max", "memoryview", "min",
    "next", "object", "oct", "ord", "pow", "range", "repr", "reversed",
    "round", "set", "slice", "sorted", "str", "sum", "super", "tuple", "zip",
})
_PURE_BUILTIN_TYPES = frozenset({
    "ArithmeticError", "AssertionError", "AttributeError", "BaseException",
    "BaseExceptionGroup", "BlockingIOError", "BrokenPipeError", "BufferError",
    "BytesWarning", "ChildProcessError", "ConnectionAbortedError",
    "ConnectionError", "ConnectionRefusedError", "ConnectionResetError",
    "DeprecationWarning", "EOFError", "EncodingWarning", "Exception",
    "ExceptionGroup", "FileExistsError", "FileNotFoundError",
    "FloatingPointError", "FutureWarning", "GeneratorExit", "ImportError",
    "ImportWarning", "IndentationError", "IndexError", "InterruptedError",
    "IsADirectoryError", "KeyError", "KeyboardInterrupt", "LookupError",
    "MemoryError", "ModuleNotFoundError", "NameError", "NotADirectoryError",
    "NotImplementedError", "OSError", "OverflowError",
    "PendingDeprecationWarning", "PermissionError", "ProcessLookupError",
    "RecursionError", "ReferenceError", "ResourceWarning", "RuntimeError",
    "RuntimeWarning", "StopAsyncIteration", "StopIteration", "SyntaxError",
    "SyntaxWarning", "SystemError", "SystemExit", "TabError", "TimeoutError",
    "TypeError", "UnboundLocalError", "UnicodeDecodeError",
    "UnicodeEncodeError", "UnicodeError", "UnicodeTranslateError",
    "UnicodeWarning", "UserWarning", "ValueError", "Warning",
    "ZeroDivisionError", "classmethod", "property", "staticmethod", "type",
})
_PURE_METHODS = frozenset({
    "add", "append", "capitalize", "casefold", "clear", "copy", "count",
    "decode", "discard", "encode", "endswith", "extend", "find", "format",
    "get", "index", "insert", "intersection", "isalnum", "isalpha", "isascii",
    "isdecimal", "isdigit", "isidentifier", "islower", "isnumeric", "isprintable",
    "isspace", "istitle", "isupper", "items", "join", "keys", "lower", "lstrip",
    "partition", "pop", "popitem", "remove", "replace", "reverse", "rfind",
    "rindex", "rjust", "rpartition", "rsplit", "rstrip", "setdefault", "sort",
    "split", "splitlines", "startswith", "strip", "swapcase", "title", "translate",
    "union", "update", "upper", "values", "zfill",
})
_PURE_BUILTIN_RECEIVER_TYPES = {
    "bytearray": bytearray,
    "bytes": bytes,
    "dict": dict,
    "frozenset": frozenset,
    "list": list,
    "set": set,
    "str": str,
    "tuple": tuple,
}
_PURE_STDLIB_CALL_RECEIVER_TYPES = {
    # These are return-type facts for exact import-resolved calls, not prefix
    # allowances for arbitrary module attributes or lookalikes.
    "hashlib.sha256": type(sha256()),
    "json.dumps": str,
    "pathlib.Path": Path,
}
_PURE_STDLIB_METHODS = frozenset({"hexdigest"})
_PURE_STDLIB_PREFIXES = (
    "collections.", "dataclasses.", "decimal.", "fractions.", "functools.",
    "itertools.", "math.", "operator.", "re.", "statistics.", "typing.",
)
_CALLBACK_BUILTINS = frozenset({"filter", "map", "max", "min", "sorted"})
_POSITIONAL_CALLBACKS = {
    "atexit.register": (0,),
    "asyncio.to_thread": (0,),
    "filter": (0,),
    "functools.reduce": (0,),
    "itertools.starmap": (0,),
    "map": (0,),
    "signal.signal": (1,),
}
_CALLBACK_KEYWORDS = frozenset({
    "action", "callback", "default_factory", "factory", "func", "function",
    "handler", "hook", "initializer", "key", "predicate", "target",
})


@dataclass(frozen=True, slots=True)
class EffectSourceEvidence:
    path: str
    sha256: str
    byte_count: int


@dataclass(frozen=True, slots=True)
class EffectImportEvidence:
    path: str
    line: int
    column: int
    module: str
    resolution: str
    resolved_path: str | None


@dataclass(frozen=True, slots=True)
class EffectDefinitionEvidence:
    path: str
    qualified_name: str
    definition_kind: str
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class EffectCallEvidence:
    path: str
    containing_definition: str | None
    target: str
    resolution: str
    line: int
    column: int
    channels: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ConsequenceEvidence:
    channel: str
    path: str
    containing_definition: str | None
    operation: str
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class ClosedEffectAudit:
    schema_version: str
    status: str
    owned_paths: tuple[str, ...]
    sources: tuple[EffectSourceEvidence, ...]
    source_set_digest: str
    imports: tuple[EffectImportEvidence, ...]
    public_definitions: tuple[EffectDefinitionEvidence, ...]
    calls: tuple[EffectCallEvidence, ...]
    consequences: tuple[ConsequenceEvidence, ...]
    blockers: tuple[str, ...]
    claim_boundary: str
    evidence_digest: str


def _canonical_value_digest(value: Any) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return _bytes_digest(raw)


def _normalize_effect_paths(paths: Iterable[str]) -> tuple[str, ...]:
    try:
        selected = tuple(paths)
    except TypeError as exc:
        raise ValueError("CLOSED_EFFECT_OWNED_PATHS_INVALID") from exc
    if not selected:
        raise ValueError("CLOSED_EFFECT_OWNED_PATHS_EMPTY")
    normalized: list[str] = []
    for value in selected:
        if type(value) is not str or not value:
            raise ValueError("CLOSED_EFFECT_OWNED_PATH_INVALID")
        candidate = value.replace("\\", "/")
        pure = PurePosixPath(candidate)
        if (
            pure.is_absolute()
            or ":" in candidate
            or any(part in {"", ".", ".."} for part in pure.parts)
            or pure.as_posix() != candidate
        ):
            raise ValueError("CLOSED_EFFECT_OWNED_PATH_INVALID:" + value)
        normalized.append(candidate)
    if len(normalized) != len(set(normalized)):
        raise ValueError("CLOSED_EFFECT_OWNED_PATH_DUPLICATE")
    return tuple(sorted(normalized))


def _effect_source_snapshot(
    root: Path,
    selected_paths: tuple[str, ...],
) -> tuple[EffectSourceEvidence, ...]:
    evidence: list[EffectSourceEvidence] = []
    for relative in selected_paths:
        try:
            target = (root / relative).resolve(strict=True)
            target.relative_to(root)
            if not target.is_file():
                raise ValueError(relative)
            raw = target.read_bytes()
        except (OSError, ValueError) as exc:
            raise ValueError("SOURCE_UNAVAILABLE:" + relative) from exc
        evidence.append(EffectSourceEvidence(
            path=relative,
            sha256=_bytes_digest(raw),
            byte_count=len(raw),
        ))
    return tuple(evidence)


def _module_names(relative: str) -> tuple[str, ...]:
    parts = list(PurePosixPath(relative).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    names = []
    if parts:
        names.append(".".join(parts))
    if len(parts) > 1 and parts[0] in {"lib", "src"}:
        names.append(".".join(parts[1:]))
    return tuple(dict.fromkeys(name for name in names if name))


def _preferred_module_name(relative: str) -> str:
    names = _module_names(relative)
    return names[-1] if names else PurePosixPath(relative).stem


def _project_module_path(root: Path, module: str) -> str | None:
    if not module:
        return None
    parts = module.split(".")
    for prefix in ((), ("src",), ("lib",)):
        base = root.joinpath(*prefix, *parts)
        for candidate in (base.with_suffix(".py"), base / "__init__.py"):
            try:
                target = candidate.resolve(strict=True)
                relative = target.relative_to(root)
            except (OSError, ValueError):
                continue
            if target.is_file():
                return relative.as_posix()
    return None


def _absolute_import_name(
    module: str | None,
    level: int,
    *,
    current_path: str,
) -> str:
    selected = module or ""
    if level == 0:
        return selected
    current = _preferred_module_name(current_path)
    package = (
        current
        if PurePosixPath(current_path).name == "__init__.py"
        else current.rpartition(".")[0]
    )
    parts = package.split(".") if package else []
    ascend = level - 1
    if ascend > len(parts):
        return selected
    prefix = parts[:len(parts) - ascend]
    if selected:
        prefix.extend(selected.split("."))
    return ".".join(prefix)


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        if parent:
            return parent + "." + node.attr
    return None


def _definition_inventory(
    trees: Mapping[str, ast.AST],
) -> tuple[
    tuple[EffectDefinitionEvidence, ...],
    frozenset[str],
    dict[str, dict[str, tuple[str, ...]]],
]:
    public: list[EffectDefinitionEvidence] = []
    all_names: set[str] = set()
    simple: dict[str, dict[str, list[str]]] = {}

    class Collector(ast.NodeVisitor):
        def __init__(self, path: str) -> None:
            self.path = path
            self.module = _preferred_module_name(path)
            self.scope: list[str] = []

        def _record(self, node: ast.AST, name: str, kind: str) -> None:
            qualified = ".".join((self.module, *self.scope, name))
            all_names.add(qualified)
            simple.setdefault(self.path, {}).setdefault(name, []).append(qualified)
            if not name.startswith("_"):
                public.append(EffectDefinitionEvidence(
                    path=self.path,
                    qualified_name=qualified,
                    definition_kind=kind,
                    line=node.lineno,
                    column=node.col_offset,
                ))

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self._record(node, node.name, "CLASS")
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._record(node, node.name, "FUNCTION")
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._record(node, node.name, "ASYNC_FUNCTION")
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()

    for path in sorted(trees):
        Collector(path).visit(trees[path])
    public.sort(key=lambda row: (
        row.path, row.line, row.column, row.qualified_name,
    ))
    stable_simple = {
        path: {
            name: tuple(sorted(values))
            for name, values in names.items()
        }
        for path, names in simple.items()
    }
    return tuple(public), frozenset(all_names), stable_simple


def _resolve_imports(
    root: Path,
    trees: Mapping[str, ast.AST],
    owned_paths: tuple[str, ...],
) -> tuple[
    tuple[EffectImportEvidence, ...],
    dict[str, dict[str, str]],
    tuple[str, ...],
]:
    owned = set(owned_paths)
    module_paths = {
        name: path
        for path in owned_paths
        for name in _module_names(path)
    }
    evidence: list[EffectImportEvidence] = []
    aliases: dict[str, dict[str, str]] = {path: {} for path in trees}
    blockers: set[str] = set()

    def resolve(module: str) -> tuple[str, str | None, str]:
        direct = module_paths.get(module)
        if direct is not None:
            return "OWNED_LOCAL", direct, _preferred_module_name(direct)
        project = _project_module_path(root, module)
        if project is not None:
            if project in owned:
                return "OWNED_LOCAL", project, _preferred_module_name(project)
            return "PROJECT_LOCAL_OUTSIDE_OWNERSHIP", project, module
        top = module.partition(".")[0]
        if top in sys.stdlib_module_names:
            return "STDLIB", None, module
        return "EXTERNAL_UNRESOLVED", None, module

    for path in sorted(trees):
        nodes = [
            node for node in ast.walk(trees[path])
            if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        nodes.sort(key=lambda node: (node.lineno, node.col_offset))
        for node in nodes:
            if isinstance(node, ast.Import):
                for imported in node.names:
                    resolution, resolved_path, canonical = resolve(imported.name)
                    bound = imported.asname or imported.name.partition(".")[0]
                    aliases[path][bound] = (
                        canonical if imported.asname else bound
                    )
                    evidence.append(EffectImportEvidence(
                        path, node.lineno, node.col_offset, imported.name,
                        resolution, resolved_path,
                    ))
                    if resolution == "PROJECT_LOCAL_OUTSIDE_OWNERSHIP":
                        blockers.add(
                            f"IMPORT_ESCAPES_OWNERSHIP:{path}:{node.lineno}:"
                            f"{resolved_path}"
                        )
                    elif resolution == "EXTERNAL_UNRESOLVED":
                        blockers.add(
                            f"EXTERNAL_IMPORT_UNACCOUNTED:{path}:{node.lineno}:"
                            f"{imported.name}"
                        )
                continue
            base = _absolute_import_name(
                node.module, node.level, current_path=path,
            )
            for imported in node.names:
                selected_module = base
                resolution, resolved_path, canonical = resolve(selected_module)
                selected_child = False
                if imported.name != "*":
                    child = ".".join(filter(None, (base, imported.name)))
                    child_resolution, child_path, child_canonical = resolve(child)
                    # ``from package import child`` executes child when it is
                    # a project module. Check that exact module even when the
                    # package __init__ itself is already inside the closure.
                    if child_resolution in {
                        "OWNED_LOCAL", "PROJECT_LOCAL_OUTSIDE_OWNERSHIP",
                    } or (
                        resolution == "EXTERNAL_UNRESOLVED"
                        and child_resolution != "EXTERNAL_UNRESOLVED"
                    ):
                        resolution, resolved_path, canonical = (
                            child_resolution, child_path, child_canonical
                        )
                        selected_module = child
                        selected_child = True
                bound = imported.asname or imported.name
                aliases[path][bound] = (
                    canonical
                    if selected_child
                    else ".".join(filter(None, (canonical, imported.name)))
                )
                evidence.append(EffectImportEvidence(
                    path, node.lineno, node.col_offset,
                    selected_module or imported.name, resolution, resolved_path,
                ))
                if imported.name == "*":
                    blockers.add(
                        f"STAR_IMPORT_UNRESOLVED:{path}:{node.lineno}:"
                        f"{selected_module}"
                    )
                if resolution == "PROJECT_LOCAL_OUTSIDE_OWNERSHIP":
                    blockers.add(
                        f"IMPORT_ESCAPES_OWNERSHIP:{path}:{node.lineno}:"
                        f"{resolved_path}"
                    )
                elif resolution == "EXTERNAL_UNRESOLVED":
                    blockers.add(
                        f"EXTERNAL_IMPORT_UNACCOUNTED:{path}:{node.lineno}:"
                        f"{selected_module or imported.name}"
                    )
    evidence.sort(key=lambda row: (
        row.path, row.line, row.column, row.module, row.resolution,
        row.resolved_path or "",
    ))
    return tuple(evidence), aliases, tuple(sorted(blockers))


def _aliased_name(raw: str, aliases: Mapping[str, str]) -> str:
    first, separator, remainder = raw.partition(".")
    replacement = aliases.get(first)
    if replacement is None:
        return raw
    return replacement + (separator + remainder if separator else "")


def _effect_channels(
    target: str,
    raw_target: str,
    call: ast.Call | None = None,
) -> tuple[str, ...]:
    channels: set[str] = set()
    method = raw_target.rpartition(".")[2]
    if target in _DYNAMIC_OPERATIONS or target.startswith("inspect."):
        channels.add("dynamic_import_eval_exec_reflection")
    if (
        target.startswith(("pathlib.Path.read_", "os.read", "os.stat", "os.path."))
        or target in {"os.listdir", "os.scandir", "os.walk"}
        or method in {"exists", "glob", "iterdir", "read", "read_bytes", "read_text", "stat"}
    ):
        channels.add("filesystem_read")
    if target == "open":
        mode: str | None = "r"
        if call is not None and len(call.args) > 1:
            mode = (
                call.args[1].value
                if isinstance(call.args[1], ast.Constant)
                and isinstance(call.args[1].value, str)
                else None
            )
        if call is not None:
            for keyword in call.keywords:
                if keyword.arg == "mode":
                    mode = (
                        keyword.value.value
                        if isinstance(keyword.value, ast.Constant)
                        and isinstance(keyword.value.value, str)
                        else None
                    )
        # A dynamic mode is conservatively both readable and writable. Static
        # modes retain the exact potential channels without executing the call.
        if mode is None or not any(flag in mode for flag in "wax") or "+" in mode:
            channels.add("filesystem_read")
        if mode is None or any(flag in mode for flag in "wax+"):
            channels.add("filesystem_write")
    if (
        target.startswith(("shutil.", "tempfile."))
        or target in {
            "os.chmod", "os.chown", "os.makedirs", "os.mkdir", "os.remove",
            "os.rename", "os.replace", "os.rmdir", "os.truncate", "os.unlink",
        }
        or method in {
            "chmod", "mkdir", "rename", "replace", "rmdir", "touch", "unlink",
            "write", "write_bytes", "write_text",
        }
    ):
        channels.add("filesystem_write")
    if target.startswith((
        "concurrent.futures.ProcessPoolExecutor", "multiprocessing.", "subprocess.",
    )) or target in {
        "os.popen", "os.system",
    } or target.startswith(("os.exec", "os.spawn")):
        channels.add("subprocess_process")
    if target.startswith((
        "asyncio.open_connection", "ftplib.", "http.", "requests.", "socket.",
        "urllib.", "websockets.",
    )):
        channels.add("network")
    if target in {"os.getenv", "os.putenv", "os.unsetenv"} or target.startswith(
        "os.environ"
    ):
        channels.add("environment")
    if target.startswith(("time.", "datetime.")):
        channels.add("clock")
    if target.startswith(("random.", "secrets.")) or target in {
        "os.urandom", "uuid.uuid1", "uuid.uuid4",
    }:
        channels.add("randomness")
    if target.startswith((
        "RPi.GPIO.", "cuda.", "gpiozero.", "serial.", "torch.cuda.", "usb.",
    )) or target == "mmap.mmap":
        channels.add("hardware_device")
    if target in {"input", "print"} or target.startswith((
        "csv.", "json.", "marshal.", "pickle.", "queue.", "socket.recv",
        "socket.send", "tomllib.", "xml.",
    )):
        channels.add("serialization_message_boundary")
    return tuple(sorted(channels))


def _call_and_consequence_inventory(
    trees: Mapping[str, ast.AST],
    aliases: Mapping[str, Mapping[str, str]],
    local_definitions: frozenset[str],
    simple_definitions: Mapping[str, Mapping[str, tuple[str, ...]]],
) -> tuple[
    tuple[EffectCallEvidence, ...],
    tuple[ConsequenceEvidence, ...],
    tuple[str, ...],
]:
    calls: list[EffectCallEvidence] = []
    consequences: set[ConsequenceEvidence] = set()
    blockers: set[str] = set()

    class Visitor(ast.NodeVisitor):
        def __init__(self, path: str) -> None:
            self.path = path
            self.module = _preferred_module_name(path)
            self.definition_stack: list[str] = []
            self.parameter_stack: list[frozenset[str]] = []
            self.injected_stack: list[frozenset[str]] = []
            self.builtin_receiver_stack: list[dict[str, type]] = []
            self.shadowed_import_stack: list[frozenset[str]] = []
            self.class_stack: list[str] = []

        @property
        def containing(self) -> str | None:
            return self.definition_stack[-1] if self.definition_stack else None

        @property
        def parameters(self) -> frozenset[str]:
            return self.parameter_stack[-1] if self.parameter_stack else frozenset()

        @property
        def injected(self) -> frozenset[str]:
            return self.injected_stack[-1] if self.injected_stack else frozenset()

        @property
        def builtin_receivers(self) -> Mapping[str, type]:
            return self.builtin_receiver_stack[-1] if self.builtin_receiver_stack else {}

        @property
        def shadowed_imports(self) -> frozenset[str]:
            return self.shadowed_import_stack[-1] if self.shadowed_import_stack else frozenset()

        def _parameters(self, node: ast.arguments) -> frozenset[str]:
            selected = [
                *(item.arg for item in node.posonlyargs),
                *(item.arg for item in node.args),
                *(item.arg for item in node.kwonlyargs),
            ]
            if node.vararg is not None:
                selected.append(node.vararg.arg)
            if node.kwarg is not None:
                selected.append(node.kwarg.arg)
            return frozenset(selected)

        @staticmethod
        def _rooted_in(node: ast.AST, names: set[str] | frozenset[str]) -> bool:
            if isinstance(node, ast.Name):
                return node.id in names
            if isinstance(node, (ast.Attribute, ast.Subscript, ast.Starred)):
                return Visitor._rooted_in(node.value, names)
            if isinstance(node, ast.NamedExpr):
                return Visitor._rooted_in(node.value, names)
            if isinstance(node, ast.IfExp):
                return Visitor._rooted_in(node.body, names) or Visitor._rooted_in(node.orelse, names)
            if isinstance(node, ast.BoolOp):
                return any(Visitor._rooted_in(value, names) for value in node.values)
            return False

        def _import_resolves_target(
            self,
            raw: str,
            target: str,
            *,
            forbidden_names: frozenset[str] | None = None,
        ) -> bool:
            root, separator, remainder = raw.partition(".")
            blocked = (
                self.injected | self.shadowed_imports
                if forbidden_names is None
                else forbidden_names
            )
            imported = aliases.get(self.path, {}).get(root)
            if imported is None or root in blocked:
                return False
            expected = imported + (separator + remainder if separator else "")
            return expected == target

        def _known_builtin_value(
            self,
            node: ast.AST,
            known: Mapping[str, type],
            *,
            forbidden_names: frozenset[str] | None = None,
        ) -> type | None:
            if isinstance(node, ast.Name):
                return known.get(node.id)
            if isinstance(node, ast.Constant):
                value_type = type(node.value)
                return value_type if value_type in _PURE_BUILTIN_RECEIVER_TYPES.values() else None
            literal_types = {
                ast.List: list,
                ast.ListComp: list,
                ast.Dict: dict,
                ast.DictComp: dict,
                ast.Set: set,
                ast.SetComp: set,
                ast.Tuple: tuple,
            }
            if type(node) in literal_types:
                return literal_types[type(node)]
            if isinstance(node, ast.IfExp):
                body_type = self._known_builtin_value(
                    node.body, known, forbidden_names=forbidden_names,
                )
                return body_type if body_type is self._known_builtin_value(
                    node.orelse, known, forbidden_names=forbidden_names,
                ) else None
            if isinstance(node, ast.Call):
                raw = _dotted_name(node.func)
                if raw is None:
                    return None
                target = _aliased_name(raw, aliases.get(self.path, {}))
                if "." not in raw:
                    candidates = simple_definitions.get(self.path, {}).get(raw, ())
                    if len(candidates) == 1:
                        target = candidates[0]
                builtin_type = _PURE_BUILTIN_RECEIVER_TYPES.get(target)
                if builtin_type is not None:
                    return builtin_type
                stdlib_type = _PURE_STDLIB_CALL_RECEIVER_TYPES.get(target)
                if stdlib_type is not None and self._import_resolves_target(
                    raw, target, forbidden_names=forbidden_names,
                ):
                    return stdlib_type
            return None

        def _scope_facts(
            self,
            body: list[ast.AST],
            parameters: frozenset[str],
            inherited_injected: frozenset[str],
        ) -> tuple[frozenset[str], dict[str, type], frozenset[str]]:
            bindings: dict[str, list[ast.AST | None]] = collections.defaultdict(list)
            rebound_names: set[str] = set()

            def bind(target: ast.AST, value: ast.AST | None) -> None:
                if isinstance(target, ast.Name):
                    bindings[target.id].append(value)
                    rebound_names.add(target.id)
                elif isinstance(target, ast.Starred):
                    bind(target.value, None)
                elif isinstance(target, (ast.Tuple, ast.List)):
                    values = value.elts if isinstance(value, (ast.Tuple, ast.List)) \
                        and len(value.elts) == len(target.elts) else [None] * len(target.elts)
                    for child, child_value in zip(target.elts, values):
                        bind(child, child_value)

            class BindingCollector(ast.NodeVisitor):
                def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                    bindings[node.name].append(None)
                    rebound_names.add(node.name)

                def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                    bindings[node.name].append(None)
                    rebound_names.add(node.name)

                def visit_ClassDef(self, node: ast.ClassDef) -> None:
                    bindings[node.name].append(None)
                    rebound_names.add(node.name)

                def visit_Lambda(self, node: ast.Lambda) -> None:
                    return

                def visit_Assign(self, node: ast.Assign) -> None:
                    for target in node.targets:
                        bind(target, node.value)
                    self.visit(node.value)

                def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
                    bind(node.target, node.value)
                    if node.value is not None:
                        self.visit(node.value)

                def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
                    bind(node.target, node.value)
                    self.visit(node.value)

                def visit_AugAssign(self, node: ast.AugAssign) -> None:
                    bind(node.target, None)
                    self.visit(node.value)

                def visit_For(self, node: ast.For) -> None:
                    bind(node.target, None)
                    self.visit(node.iter)
                    for statement in (*node.body, *node.orelse):
                        self.visit(statement)

                visit_AsyncFor = visit_For

                def visit_comprehension(self, node: ast.comprehension) -> None:
                    bind(node.target, None)
                    self.visit(node.iter)
                    for condition in node.ifs:
                        self.visit(condition)

                def visit_With(self, node: ast.With) -> None:
                    for item in node.items:
                        self.visit(item.context_expr)
                        if item.optional_vars is not None:
                            bind(item.optional_vars, None)
                    for statement in node.body:
                        self.visit(statement)

                visit_AsyncWith = visit_With

                def visit_Import(self, node: ast.Import) -> None:
                    for item in node.names:
                        bindings[item.asname or item.name.partition(".")[0]].append(None)

                def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
                    for item in node.names:
                        bindings[item.asname or item.name].append(None)

                def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
                    if node.name:
                        bindings[node.name].append(None)
                    if node.type is not None:
                        self.visit(node.type)
                    for statement in node.body:
                        self.visit(statement)

                def visit_Delete(self, node: ast.Delete) -> None:
                    for target in node.targets:
                        bind(target, None)

            collector = BindingCollector()
            for statement in body:
                collector.visit(statement)
            for name in parameters:
                bindings[name].append(None)
                rebound_names.add(name)

            injected = set(inherited_injected) | set(parameters)
            changed = True
            while changed:
                changed = False
                for name, values in bindings.items():
                    if name not in injected and any(
                        value is not None and self._rooted_in(value, injected)
                        for value in values
                    ):
                        injected.add(name)
                        changed = True

            known: dict[str, type] = {}
            changed = True
            while changed:
                changed = False
                for name, values in bindings.items():
                    if name in injected or name in known or len(values) != 1 or values[0] is None:
                        continue
                    value_type = self._known_builtin_value(
                        values[0],
                        known,
                        forbidden_names=frozenset(injected | rebound_names),
                    )
                    if value_type is not None:
                        known[name] = value_type
                        changed = True
            return frozenset(injected), known, frozenset(
                self.shadowed_imports | rebound_names
            )

        def _push_scope(self, body: list[ast.AST], parameters: frozenset[str]) -> None:
            injected, known, shadowed = self._scope_facts(body, parameters, self.injected)
            self.parameter_stack.append(parameters)
            self.injected_stack.append(injected)
            self.builtin_receiver_stack.append(known)
            self.shadowed_import_stack.append(shadowed)

        def _pop_scope(self) -> None:
            self.shadowed_import_stack.pop()
            self.builtin_receiver_stack.pop()
            self.injected_stack.pop()
            self.parameter_stack.pop()

        def visit_Module(self, node: ast.Module) -> None:
            self._push_scope(node.body, frozenset())
            self.generic_visit(node)
            self._pop_scope()

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            qualified = ".".join((self.module, *self.class_stack, node.name))
            self.class_stack.append(node.name)
            self.definition_stack.append(qualified)
            self._push_scope(node.body, frozenset())
            self.generic_visit(node)
            self._pop_scope()
            self.definition_stack.pop()
            self.class_stack.pop()

        def _visit_function(
            self, node: ast.FunctionDef | ast.AsyncFunctionDef,
        ) -> None:
            scope = (*self.class_stack, node.name)
            qualified = ".".join((self.module, *scope))
            self.definition_stack.append(qualified)
            self._push_scope(node.body, self._parameters(node.args))
            self.generic_visit(node)
            self._pop_scope()
            self.definition_stack.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._visit_function(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._visit_function(node)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            # Lambda defaults execute in the enclosing scope, while the body
            # has its own injected parameters and local named-expression facts.
            for default in (*node.args.defaults, *node.args.kw_defaults):
                if default is not None:
                    self.visit(default)
            self._push_scope([node.body], self._parameters(node.args))
            self.visit(node.body)
            self._pop_scope()

        def _target(self, node: ast.Call) -> tuple[str, str]:
            raw = _dotted_name(node.func) or "<dynamic-call-target>"
            target = _aliased_name(raw, aliases.get(self.path, {}))
            if raw.startswith("self.") and self.class_stack:
                target = ".".join((
                    self.module, *self.class_stack, raw.removeprefix("self."),
                ))
            elif "." not in raw:
                candidates = simple_definitions.get(self.path, {}).get(raw, ())
                if len(candidates) == 1:
                    target = candidates[0]
            else:
                local_candidate = ".".join((self.module, target))
                if local_candidate in local_definitions:
                    target = local_candidate
            return raw, target

        def _record_consequences(
            self, channels: tuple[str, ...], node: ast.AST, operation: str,
        ) -> None:
            for channel in channels:
                consequences.add(ConsequenceEvidence(
                    channel=channel,
                    path=self.path,
                    containing_definition=self.containing,
                    operation=operation,
                    line=node.lineno,
                    column=node.col_offset,
                ))

        def _injected_callbacks(self, node: ast.Call, target: str) -> set[str]:
            selected: set[str] = set()
            raw = _dotted_name(node.func)
            if raw:
                root_name = raw.partition(".")[0]
                if root_name in self.injected:
                    selected.add(root_name)
            callback_nodes: list[ast.AST] = []
            for index in _POSITIONAL_CALLBACKS.get(target, ()):
                if index < len(node.args):
                    callback_nodes.append(node.args[index])
            if target in _CALLBACK_BUILTINS:
                callback_nodes.extend(
                    keyword.value for keyword in node.keywords
                    if keyword.arg == "key"
                )
            callback_nodes.extend(
                keyword.value for keyword in node.keywords
                if keyword.arg in _CALLBACK_KEYWORDS
            )
            for callback in callback_nodes:
                raw_callback = _dotted_name(callback)
                if raw_callback:
                    root_name = raw_callback.partition(".")[0]
                    if root_name in self.injected:
                        selected.add(root_name)
            return selected

        def visit_Call(self, node: ast.Call) -> None:
            raw, target = self._target(node)
            channels = set(_effect_channels(target, raw, node))
            injected = self._injected_callbacks(node, target)
            if injected:
                channels.add("callback_injected_callable")
                for name in injected:
                    blockers.add(
                        f"INJECTED_CALLABLE_UNRESOLVED:{self.path}:"
                        f"{node.lineno}:{name}"
                    )
            if target in _DYNAMIC_OPERATIONS or target.startswith("inspect."):
                blockers.add(
                    f"DYNAMIC_EXECUTION_UNRESOLVED:{self.path}:"
                    f"{node.lineno}:{node.col_offset}:{target}"
                )
                resolution = "DYNAMIC_UNRESOLVED"
            elif injected:
                resolution = "INJECTED_CALLABLE_UNRESOLVED"
            elif target in local_definitions:
                resolution = "OWNED_LOCAL_DEFINITION"
            elif target in _PURE_BUILTINS:
                resolution = "PURE_BUILTIN"
            elif not channels \
                    and target in _PURE_STDLIB_CALL_RECEIVER_TYPES \
                    and self._import_resolves_target(raw, target):
                resolution = "PURE_STDLIB"
            elif isinstance(node.func, ast.Attribute) \
                    and node.func.attr in _PURE_STDLIB_METHODS \
                    and (receiver_type := self._known_builtin_value(
                        node.func.value, self.builtin_receivers,
                    )) is not None \
                    and hasattr(receiver_type, node.func.attr):
                resolution = "PURE_STDLIB_METHOD"
            elif isinstance(node.func, ast.Attribute) \
                    and isinstance(node.func.value, ast.Name) \
                    and node.func.value.id not in (
                        self.injected | self.shadowed_imports
                    ) \
                    and (receiver_type := _PURE_BUILTIN_RECEIVER_TYPES.get(
                        node.func.value.id
                    )) is not None \
                    and node.func.attr in _PURE_METHODS \
                    and hasattr(receiver_type, node.func.attr):
                resolution = "PURE_BUILTIN_METHOD"
            elif isinstance(node.func, ast.Attribute) \
                    and node.func.attr in _PURE_METHODS \
                    and (receiver_type := self._known_builtin_value(
                        node.func.value, self.builtin_receivers,
                    )) is not None \
                    and hasattr(receiver_type, node.func.attr):
                resolution = "PURE_BUILTIN_METHOD"
            elif target.startswith(_PURE_STDLIB_PREFIXES):
                resolution = "PURE_STDLIB"
            elif channels:
                resolution = "ACCOUNTED_CONSEQUENCE"
            elif target in _PURE_BUILTIN_TYPES:
                resolution = "PURE_BUILTIN_TYPE"
            else:
                resolution = "UNRESOLVED"
                blockers.add(
                    f"CALL_TARGET_UNRESOLVED:{self.path}:"
                    f"{node.lineno}:{node.col_offset}:{target}"
                )
            stable_channels = tuple(sorted(channels))
            calls.append(EffectCallEvidence(
                path=self.path,
                containing_definition=self.containing,
                target=target,
                resolution=resolution,
                line=node.lineno,
                column=node.col_offset,
                channels=stable_channels,
            ))
            self._record_consequences(stable_channels, node, target)
            self.generic_visit(node)

        def visit_Attribute(self, node: ast.Attribute) -> None:
            raw = _dotted_name(node)
            if raw:
                target = _aliased_name(raw, aliases.get(self.path, {}))
                if target == "os.environ":
                    self._record_consequences(
                        ("environment",), node, target,
                    )
            self.generic_visit(node)

    for path in sorted(trees):
        Visitor(path).visit(trees[path])
    calls.sort(key=lambda row: (
        row.path, row.line, row.column, row.target, row.resolution,
    ))
    stable_consequences = tuple(sorted(consequences, key=lambda row: (
        row.channel, row.path, row.line, row.column, row.operation,
        row.containing_definition or "",
    )))
    return tuple(calls), stable_consequences, tuple(sorted(blockers))


def _effect_audit_body(audit: ClosedEffectAudit) -> dict[str, Any]:
    return {
        "schema_version": audit.schema_version,
        "status": audit.status,
        "owned_paths": list(audit.owned_paths),
        "sources": [
            {"path": row.path, "sha256": row.sha256, "byte_count": row.byte_count}
            for row in audit.sources
        ],
        "source_set_digest": audit.source_set_digest,
        "imports": [{
            "path": row.path,
            "line": row.line,
            "column": row.column,
            "module": row.module,
            "resolution": row.resolution,
            "resolved_path": row.resolved_path,
        } for row in audit.imports],
        "public_definitions": [{
            "path": row.path,
            "qualified_name": row.qualified_name,
            "definition_kind": row.definition_kind,
            "line": row.line,
            "column": row.column,
        } for row in audit.public_definitions],
        "calls": [{
            "path": row.path,
            "containing_definition": row.containing_definition,
            "target": row.target,
            "resolution": row.resolution,
            "line": row.line,
            "column": row.column,
            "channels": list(row.channels),
        } for row in audit.calls],
        "consequences": [{
            "channel": row.channel,
            "path": row.path,
            "containing_definition": row.containing_definition,
            "operation": row.operation,
            "line": row.line,
            "column": row.column,
        } for row in audit.consequences],
        "blockers": list(audit.blockers),
        "claim_boundary": audit.claim_boundary,
    }


def _seal_effect_audit(
    *,
    owned_paths: tuple[str, ...],
    sources: tuple[EffectSourceEvidence, ...],
    imports: tuple[EffectImportEvidence, ...] = (),
    public_definitions: tuple[EffectDefinitionEvidence, ...] = (),
    calls: tuple[EffectCallEvidence, ...] = (),
    consequences: tuple[ConsequenceEvidence, ...] = (),
    blockers: Iterable[str] = (),
) -> ClosedEffectAudit:
    if any(row.channel not in _EFFECT_CHANNELS for row in consequences):
        raise ValueError("CLOSED_EFFECT_CHANNEL_INVALID")
    stable_blockers = tuple(sorted(set(blockers)))
    source_rows = [
        {"path": row.path, "sha256": row.sha256, "byte_count": row.byte_count}
        for row in sources
    ]
    selected = ClosedEffectAudit(
        schema_version=_EFFECT_AUDIT_SCHEMA,
        status="UNKNOWN" if stable_blockers else "CLOSED",
        owned_paths=owned_paths,
        sources=sources,
        source_set_digest=_canonical_value_digest(source_rows),
        imports=imports,
        public_definitions=public_definitions,
        calls=calls,
        consequences=consequences,
        blockers=stable_blockers,
        claim_boundary=(
            "CLOSED establishes only that this exact Python owned-source set "
            "was parsed and every statically visible call, project-local import, "
            "callback uncertainty, dynamic operation and enumerated consequence "
            "channel was accounted for at these source bytes. It never infers an "
            "original semantic kind, DOES_NOT_APPLY decision, runtime truth, "
            "external authority, or absence of effects outside this closure."
        ),
        evidence_digest="",
    )
    digest = _canonical_value_digest(_effect_audit_body(selected))
    return ClosedEffectAudit(
        **{
            field: getattr(selected, field)
            for field in (
                "schema_version", "status", "owned_paths", "sources",
                "source_set_digest", "imports", "public_definitions", "calls",
                "consequences", "blockers", "claim_boundary",
            )
        },
        evidence_digest=digest,
    )


def closed_effect_audit_document(audit: ClosedEffectAudit) -> dict[str, Any]:
    """Return the canonical JSON-compatible evidence document."""

    if type(audit) is not ClosedEffectAudit:
        raise ValueError("CLOSED_EFFECT_AUDIT_INVALID")
    body = _effect_audit_body(audit)
    if audit.evidence_digest != _canonical_value_digest(body):
        raise ValueError("CLOSED_EFFECT_AUDIT_DIGEST_INVALID")
    return {**body, "evidence_digest": audit.evidence_digest}


def audit_closed_effects(
    root: str | Path,
    owned_paths: Iterable[str],
    *,
    expected_source_digests: Mapping[str, str] | None = None,
) -> ClosedEffectAudit:
    """Audit static effect closure without assigning any semantic kind.

    The explicit owned-path set is the entire review universe. Project-local
    imports outside it, external dependencies, unresolved calls, callbacks and
    dynamic execution are blockers rather than invitations to infer absence.
    """

    selected_root = Path(root).resolve(strict=True)
    selected_paths = _normalize_effect_paths(owned_paths)
    try:
        opening = _effect_source_snapshot(selected_root, selected_paths)
    except ValueError as exc:
        return _seal_effect_audit(
            owned_paths=selected_paths,
            sources=(),
            blockers=(str(exc),),
        )
    blockers: set[str] = set()
    if expected_source_digests is not None:
        if type(expected_source_digests) is not dict or set(expected_source_digests) != set(selected_paths):
            blockers.add("EXPECTED_SOURCE_DENOMINATOR_DIFFERS")
        else:
            for source in opening:
                if expected_source_digests.get(source.path) != source.sha256:
                    blockers.add("SOURCE_DIGEST_DIFFERS:" + source.path)

    trees: dict[str, ast.AST] = {}
    for source in opening:
        if PurePosixPath(source.path).suffix != ".py":
            blockers.add("UNSUPPORTED_LANGUAGE:" + source.path)
            continue
        try:
            raw = (selected_root / source.path).read_bytes()
            trees[source.path] = ast.parse(raw, filename=source.path)
        except SyntaxError as exc:
            blockers.add(
                f"PYTHON_SYNTAX_ERROR:{source.path}:"
                f"{exc.lineno or 0}:{exc.offset or 0}"
            )
        except OSError:
            blockers.add("SOURCE_UNAVAILABLE:" + source.path)

    imports, aliases, import_blockers = _resolve_imports(
        selected_root, trees, selected_paths,
    )
    blockers.update(import_blockers)
    public, all_definitions, simple = _definition_inventory(trees)
    calls, consequences, call_blockers = _call_and_consequence_inventory(
        trees, aliases, all_definitions, simple,
    )
    blockers.update(call_blockers)
    try:
        closing = _effect_source_snapshot(selected_root, selected_paths)
    except ValueError as exc:
        blockers.add(str(exc))
        closing = ()
    if closing != opening:
        opening_by_path = {row.path: row.sha256 for row in opening}
        closing_by_path = {row.path: row.sha256 for row in closing}
        for path in selected_paths:
            if opening_by_path.get(path) != closing_by_path.get(path):
                blockers.add("SOURCE_CHANGED_DURING_AUDIT:" + path)
    return _seal_effect_audit(
        owned_paths=selected_paths,
        sources=opening,
        imports=imports,
        public_definitions=public,
        calls=calls,
        consequences=consequences,
        blockers=blockers,
    )


__all__ = [
    "ClosedEffectAudit",
    "ConsequenceEvidence",
    "EffectCallEvidence",
    "EffectDefinitionEvidence",
    "EffectImportEvidence",
    "EffectSourceEvidence",
    "apply_original_kind_profile",
    "audit_closed_effects",
    "closed_effect_audit_document",
]
