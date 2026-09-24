"""Accountable party specification (ACTOR): decisions attributed to accountable parties.

An ACTOR certificate establishes the bound party, its control surface, decision classes,
and non-transferable accountability. An instrument executes while the actor answers.
Attribution requires independent witnessing; self-attribution alone cannot establish
accountability. Counts are dimensionless.
"""
from __future__ import annotations

from typing import Any
from .common import (Budget, Refuted, Unavailable, digest, integer, need, obj, same, seq, text)


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget, **_: Any) -> dict:
    actor_id = text(need(artifact, "actor_id"))
    control_surface = seq(need(artifact, "control_surface"), budget)
    decision_classes = [text(c) for c in seq(need(artifact, "decision_classes"), budget)]
    admitted_spaces = [text(s) for s in seq(need(artifact, "admitted_spaces"), budget)]
    boundary = obj(need(artifact, "instrument_boundary"), {"actor", "instruments"})

    # Check 1: identity (ACTOR-1.1)
    if check == "identity":
        control_keys = seq(need(inputs, "control_keys"), budget)
        same(digest(control_keys), digest(control_surface), "control keys do not match artifact surface")
        actor_components = {text(c) for c in seq(boundary["actor"], budget)}
        instrument_components = {text(c) for c in seq(boundary["instruments"], budget)}
        if actor_components & instrument_components:
            raise Refuted("instrument boundary overlap: component on both sides")
        return {"actor_id": actor_id, "control_keys": len(control_keys),
                "decision_classes": decision_classes, "admitted_spaces": admitted_spaces}

    # Check 2: delegation (ACTOR-2.1)
    elif check == "delegation":
        delegation_events = seq(need(inputs, "delegation_events"), budget, nonempty=False)
        same(digest(delegation_events), need(artifact, "delegations_digest"), "delegation events differ")
        active_delegations: dict[str, list] = {}
        for event in delegation_events:
            obj(event, {"event", "position", "delegate", "subset", "interval"})
            kind = text(event["event"])
            delegate = text(event["delegate"])
            subset = [text(s) for s in seq(event["subset"], budget)]
            if not set(subset) <= set(decision_classes):
                raise Refuted("delegation conveys authority outside actor's decision classes")
            if kind == "delegation":
                active_delegations[delegate] = subset
            elif kind == "revocation":
                active_delegations.pop(delegate, None)
            elif kind == "rotation":
                pass
            else:
                raise Refuted(f"unknown actor event kind: {kind}")
        return {"delegation_events": len(delegation_events), "active_delegates": len(active_delegations)}

    # Check 3: accountability (ACTOR-3.2)
    elif check == "accountability":
        witnesses = seq(need(inputs, "witness_attributions"), budget)
        for w in witnesses:
            obj(w, {"witness_id", "decision_id", "actor_id"})
            if text(w["witness_id"]) == actor_id:
                raise Refuted("sole witness violation: actor cannot be sole witness of own attribution")
            if text(w["actor_id"]) != actor_id:
                raise Refuted("witness attributions must bind the declared actor")
        return {"witnesses_verified": len(witnesses)}

    # Check 4: attribution (ACTOR-4.2)
    elif check == "attribution":
        decisions = seq(need(inputs, "decisions"), budget)
        same(digest(decisions), need(artifact, "decisions_digest"), "decision trace differs")
        attributed_decisions = set()
        for idx, decision in enumerate(decisions):
            obj(decision, {"decision_id", "position", "decision_class", "actor", "instrument", "timestamp"})
            if decision["position"] != idx:
                raise Refuted("decisions are not contiguous in position")
            dec_id = text(decision["decision_id"])
            if dec_id in attributed_decisions:
                raise Refuted(f"duplicate attribution for decision {dec_id}")
            attributed_decisions.add(dec_id)
            if text(decision["actor"]) != actor_id:
                raise Refuted(f"decision attributed to undeclared actor {decision['actor']}")
            d_class = text(decision["decision_class"])
            if d_class not in decision_classes:
                raise Refuted(f"decision class {d_class} not declared in actor classes")
            if decision["instrument"] in boundary["actor"]:
                raise Refuted("instrument is an actor component")
        return {"decisions_attributed": len(attributed_decisions), "unattributed": 0}

    raise Unavailable(f"unsupported ACTOR check: {check}")
