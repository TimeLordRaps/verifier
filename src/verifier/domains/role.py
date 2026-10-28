"""Bounded ROLE class declarations and retained occupancy replay.

ROLE is a class, never a bearer or an authorization decision. This adapter checks
declared records only; it does not authenticate people, qualifications or grants.
"""
from __future__ import annotations

from typing import Any

from .common import Budget, Refuted, Unavailable, digest, integer, need, obj, same, seq, text


def _names(value: Any, budget: Budget, *, nonempty: bool = False) -> list[str]:
    names = [text(item) for item in seq(value, budget, nonempty=nonempty)]
    if len(set(names)) != len(names):
        raise Refuted("duplicate role class facet")
    return names


def _facets(artifact: dict, budget: Budget) -> dict:
    role_class_id = text(need(artifact, "role_class_id"))
    coordinate = text(need(artifact, "coordinate"))
    authority = _names(need(artifact, "authority"), budget)
    qualifications = _names(need(artifact, "qualifications"), budget)
    limit = integer(need(artifact, "bearer_limit"), minimum=1)
    bearer_classes = _names(need(artifact, "admissible_bearer_classes"), budget, nonempty=True)
    if not set(bearer_classes) <= {"human", "bot"}:
        raise Refuted("role class admits an undeclared bearer class")
    # These are declarations, not proof that a bearer has a qualification or a grant.
    return {"role_class_id": role_class_id, "coordinate": coordinate,
            "authority_classes": len(authority), "qualifications": len(qualifications),
            "bearer_limit": limit, "admissible_bearer_classes": bearer_classes}


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget, **_: Any) -> dict:
    facets = _facets(artifact, budget)
    if check == "facets":
        return facets
    if check != "occupancy":
        raise Unavailable(f"unsupported ROLE check: {check}")

    events = seq(need(inputs, "occupancy_events"), budget)
    same(digest(events), need(artifact, "occupancy_events_digest"), "role occupancy trace differs")
    occupants: dict[str, str] = {}
    allowed = set(facets["admissible_bearer_classes"])
    for position, raw in enumerate(events):
        event = obj(raw)
        if integer(need(event, "position")) != position:
            raise Refuted("role occupancy events are not contiguous")
        kind = text(need(event, "event"))
        if kind == "take":
            obj(event, {"position", "event", "bearer_id", "bearer_class"})
            bearer = text(event["bearer_id"])
            bearer_class = text(event["bearer_class"])
            if bearer_class not in allowed or bearer in occupants:
                raise Refuted("role taking contradicts declared bearer class or occupancy")
            occupants[bearer] = bearer_class
        elif kind == "leave":
            obj(event, {"position", "event", "bearer_id"})
            bearer = text(event["bearer_id"])
            if bearer not in occupants:
                raise Refuted("role leaving has no preceding taking")
            del occupants[bearer]
        elif kind == "handover":
            obj(event, {"position", "event", "leaving", "taking", "bearer_class"})
            leaving = text(event["leaving"])
            taking = text(event["taking"])
            bearer_class = text(event["bearer_class"])
            if leaving not in occupants or taking in occupants or leaving == taking:
                raise Refuted("role handover is not a paired leaving and taking")
            if bearer_class not in allowed:
                raise Refuted("role handover takes an inadmissible bearer class")
            del occupants[leaving]
            occupants[taking] = bearer_class
        else:
            raise Refuted(f"unsupported role occupancy event: {kind}")
        if len(occupants) > facets["bearer_limit"]:
            raise Refuted("role simultaneous bearer limit exceeded")
    current = _names(need(artifact, "current_occupants"), budget)
    if set(current) != set(occupants):
        raise Refuted("role current occupants differ from retained replay")
    return {"events_replayed": len(events), "declared_occupants_after_trace": sorted(occupants),
            "live_occupancy": "NOT_ESTABLISHED", "occupant_classes_declared_only": True}
