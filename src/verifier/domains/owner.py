"""Holding and consequence boundary specification (OWNER): artifact rights, duties, and accountability floors.

An OWNER certificate establishes the consequence limbs (responsibility, authority,
blame, fault, consent, privacy) held over an artifact by an ACTOR. An ACTOR can
freeze, seal, or thaw artifacts, and is held responsibly connected to the TRUST,
RUST, and ROT of artifacts they own. Holding never alters computational verdicts
or evidence bytes. Every discharge-duty must terminate in an accountable person.
"""
from __future__ import annotations

from typing import Any
from .common import (Budget, Refuted, Unavailable, digest, integer, need, obj, same, seq, text)

CONSEQUENCE_LIMBS = frozenset({
    "responsibility",
    "authority",
    "blame",
    "fault",
    "consent",
    "privacy",
})

LIMB_KINDS = frozenset({
    "right",
    "discharge_duty",
    "answering_duty",
})


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget, **_: Any) -> dict:
    holder_actor_id = text(need(artifact, "holder_actor_id"))
    held_object_coord = text(need(artifact, "held_object_coordinate"))
    held_object_digest = text(need(artifact, "held_object_digest"))
    limbs = [text(l) for l in seq(need(artifact, "limbs"), budget)]
    limbs_kind = obj(need(artifact, "limbs_kind"))

    # Check 1: limbs (OWNER-1.3)
    if check == "limbs":
        unknown_limbs = set(limbs) - CONSEQUENCE_LIMBS
        if unknown_limbs:
            raise Refuted(f"unknown consequence limbs: {sorted(unknown_limbs)}; must be one of {sorted(CONSEQUENCE_LIMBS)}")
        for limb in limbs:
            if limb not in limbs_kind:
                raise Refuted(f"limb {limb} missing limb kind mapping")
            kind = text(limbs_kind[limb])
            if kind not in LIMB_KINDS:
                raise Refuted(f"limb kind {kind} must be one of {sorted(LIMB_KINDS)}")
        instrument = obj(need(artifact, "instrument"), {"id", "issuing_authority"})
        text(instrument["id"])
        text(instrument["issuing_authority"])
        term = obj(need(artifact, "term"), {"start", "end"})
        integer(term["start"])
        integer(term["end"])
        if term["end"] < term["start"]:
            raise Refuted("term end precedes term start")
        return {"holder_actor_id": holder_actor_id, "held_object": held_object_coord,
                "limbs": limbs, "term_window": [term["start"], term["end"]]}

    # Check 2: lifecycle (OWNER-2.1)
    elif check == "lifecycle":
        events = seq(need(inputs, "events"), budget)
        same(digest(events), need(artifact, "events_digest"), "events digest differs")
        current_limbs = set(limbs)
        sealed = False
        frozen = False
        for idx, event in enumerate(events):
            obj(event, {"event", "position", "target_limb", "actor_id"})
            if event["position"] != idx:
                raise Refuted("events not contiguous in position")
            action = text(event["event"])
            actor = text(event["actor_id"])
            if action in ("freeze", "seal", "thaw"):
                if action == "freeze":
                    frozen = True
                elif action == "seal":
                    sealed = True
                elif action == "thaw":
                    if not sealed:
                        raise Refuted("thaw requires previous seal")
                    sealed = False
            elif action == "transfer":
                target = text(event["target_limb"])
                if target not in current_limbs:
                    raise Refuted(f"cannot transfer unheld limb: {target}")
            elif action == "revocation":
                target = text(event["target_limb"])
                current_limbs.discard(target)
            elif action == "lapse":
                pass
            else:
                raise Refuted(f"unknown holding lifecycle action: {action}")
        return {"events_replayed": len(events), "frozen": frozen, "sealed": sealed}

    # Check 3: independence (OWNER-3.1)
    elif check == "independence":
        # Holding never alters computational verdicts or evidence bytes.
        held_verdict = obj(need(inputs, "held_verdict"), {"status", "computed_digest"})
        same(held_verdict["computed_digest"], held_object_digest, "held object digest altered")
        if held_verdict["status"] not in ("PASS", "FAIL", "UNKNOWN", "REJECTED"):
            raise Refuted("invalid held verdict status")
        return {"verdict_independence_preserved": True, "held_verdict": held_verdict["status"]}

    # Check 4: accountability (OWNER-4.5)
    elif check == "accountability":
        holdings_chain = seq(need(inputs, "holdings_chain"), budget)
        origin = text(need(artifact, "chain_origin"))
        if not holdings_chain or text(holdings_chain[0].get("id")) != origin:
            raise Refuted("holdings chain does not begin at declared origin")
        answering_duties = obj(need(inputs, "answering_duties"))
        # Accountability floor: every discharge duty has an answering duty terminating in a natural person.
        discharge_duties = [l for l in limbs if limbs_kind.get(l) == "discharge_duty"]
        for duty in discharge_duties:
            if duty not in answering_duties:
                raise Refuted(f"accountability floor violated: discharge duty '{duty}' has no answering duty")
            terminal = text(answering_duties[duty])
            if not (terminal.startswith("human:") or terminal.startswith("actor:person:")):
                raise Refuted(f"answering duty for '{duty}' does not terminate in a natural person: {terminal}")
        return {"accountability_floor_satisfied": True, "discharge_duties": len(discharge_duties),
                "chain_length": len(holdings_chain)}

    raise Unavailable(f"unsupported OWNER check: {check}")
