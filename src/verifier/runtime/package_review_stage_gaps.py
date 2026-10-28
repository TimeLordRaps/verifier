"""Run a package review stage past a stale specialization label, never dropping it.

Every review stage refuses a specialization label that its own audited catalog no
longer supports.  That refusal is right for a maintainer, who must decide.  A
polish receipt still has to be produced, and it must not lose a reviewed label or
its obligations on its own.  ``run_stage`` therefore hides one such label from the
stage, lets the stage review everything it does support, and then puts the label,
its decision and its obligations back exactly as they were.  The label stays in
force, its obligations stay open, and the gap is reported so the developer knows
what to review.  The primary kind and every other refusal still abort.

The same runner serves a stage that reviews one exact file set.  A file added after
that review lands in the object by fallback ownership; the stage would refuse it.
In record mode the file is hidden from the stage and put back afterwards, and any
refutation the stage wrote is reopened, because absence over the reviewed files says
nothing about the new one.  An APPLIES finding cites reviewed bytes, so it stands.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Mapping
from copy import deepcopy
import re
from typing import Any

_LABEL_CONFLICT = re.compile(
    r"^[A-Z_]*LABEL_CONFLICT:(?P<object_id>[^:]+):(?P<kind>[A-Z]+)$"
)
STALE_SPECIALIZATION_LABEL = "STALE_SPECIALIZATION_LABEL"
UNREVIEWED_OWNED_PATHS = "UNREVIEWED_OWNED_PATHS"


def _detach(row: dict[str, Any], kind: str) -> tuple[int, Any, dict[str, Any]]:
    """Remove one specialization label with its decision and obligations."""
    index = row["specializations"].index(kind)
    row["specializations"].pop(index)
    decision = row["classification"].get(kind)
    # Reviews that own a fixed kind set need the key; give them the open question.
    row["classification"][kind] = {
        "status": "UNRESOLVED",
        "reason": (
            "Migration retains this applicability question. Static ownership "
            "alone cannot refute a " + kind + " role."
        ),
        "evidence": [],
    }
    obligations = {
        name: row["obligations"].pop(name)
        for name in list(row["obligations"])
        if name.split("-", 1)[0] == kind
    }
    return index, decision, obligations


def _restore(
    row: dict[str, Any], kind: str, stash: tuple[int, Any, dict[str, Any]]
) -> None:
    """Put a hidden label back, replacing anything the stage wrote for it."""
    index, decision, obligations = stash
    if kind not in row["specializations"]:
        row["specializations"].insert(min(index, len(row["specializations"])), kind)
    if decision is not None:
        row["classification"][kind] = decision
    for name in [name for name in row["obligations"] if name.split("-", 1)[0] == kind]:
        del row["obligations"][name]
    row["obligations"].update(obligations)


def _surface_path(surface: str) -> str | None:
    """Return the repository path a surface string names, if it names one."""
    scheme, separator, rest = surface.partition(":")
    if not separator or not scheme:
        return None
    if scheme == "file":
        return rest
    return rest.split(":", 1)[0]


def _owned_files(row: Mapping[str, Any]) -> set[str]:
    return {
        surface.removeprefix("file:")
        for surface in row.get("surfaces", ())
        if type(surface) is str and surface.startswith("file:")
    }


def run_stage(
    stage: Callable[[Mapping[str, dict[str, Any]]], dict[str, dict[str, Any]]],
    rows: Mapping[str, dict[str, Any]],
    *,
    name: str,
    record_gaps: bool = False,
    report: list[dict[str, Any]] | None = None,
    reviewed: Mapping[str, Collection[str]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Apply ``stage`` to ``rows``; with ``record_gaps`` hide stale labels first.

    ``rows`` is never mutated.  A refusal hides a label only when it names a
    specialization the object holds, once per label; anything else is re-raised.
    ``reviewed`` maps an object to the exact files its stage reviewed; files it
    owns beyond those are hidden from the stage and restored afterwards.
    """
    if not record_gaps:
        return stage(rows)
    working: Mapping[str, dict[str, Any]] = rows
    stashes: dict[tuple[str, str], tuple[int, Any, dict[str, Any]]] = {}
    unreviewed: dict[str, tuple[list[str], list[str]]] = {}
    for object_id, paths in (reviewed or {}).items():
        row = rows.get(object_id)
        if type(row) is not dict:
            continue
        owned = _owned_files(row)
        extra = sorted(owned - set(paths))
        if not extra or not set(paths) <= owned:
            continue
        if working is rows:
            working = dict(rows)
        if working[object_id] is row:
            working[object_id] = deepcopy(row)
        original = list(row["surfaces"])
        hidden = set(extra)
        working[object_id]["surfaces"] = [
            surface for surface in original if _surface_path(surface) not in hidden
        ]
        unreviewed[object_id] = (extra, original)
    while True:
        try:
            result = stage(working)
            break
        except ValueError as error:
            match = _LABEL_CONFLICT.match(str(error))
            if match is None:
                raise
            object_id, kind = match["object_id"], match["kind"]
            row = working.get(object_id)
            if (
                (object_id, kind) in stashes
                or type(row) is not dict
                or row.get("kind") == kind
                or kind not in row.get("specializations", ())
            ):
                raise
            if working is rows:
                working = dict(rows)
            if working[object_id] is rows.get(object_id):
                working[object_id] = deepcopy(working[object_id])
            stashes[(object_id, kind)] = _detach(working[object_id], kind)
    for object_id, (extra, original) in unreviewed.items():
        row = result[object_id]
        row["surfaces"] = list(original)
        for kind, decision in row["classification"].items():
            if decision.get("status") == "DOES_NOT_APPLY":
                row["classification"][kind] = {
                    "status": "UNRESOLVED",
                    "reason": (
                        "Migration retains this applicability question. Static "
                        "ownership alone cannot refute a " + kind + " role."
                    ),
                    "evidence": [],
                }
        if report is not None:
            report.append(
                {
                    "stage": name,
                    "object_id": object_id,
                    "gap": UNREVIEWED_OWNED_PATHS,
                    "paths": extra,
                }
            )
    for (object_id, kind), stash in stashes.items():
        _restore(result[object_id], kind, stash)
        if report is not None:
            report.append(
                {
                    "stage": name,
                    "object_id": object_id,
                    "kind": kind,
                    "gap": STALE_SPECIALIZATION_LABEL,
                }
            )
    return result


__all__ = ("STALE_SPECIALIZATION_LABEL", "UNREVIEWED_OWNED_PATHS", "run_stage")
