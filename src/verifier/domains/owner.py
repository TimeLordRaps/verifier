"""Holding and consequence boundary specification (OWNER): artifact rights, duties, and accountability floors.

An OWNER certificate establishes the consequence limbs (responsibility, authority,
blame, fault, consent, privacy) held over an artifact by an ACTOR. An ACTOR can
freeze, seal, or thaw artifacts, and is held responsibly connected to the TRUST,
RUST, and ROT of artifacts they own. Holding never alters computational verdicts
or evidence bytes, but a declared verdict is not a replayed one, so verdict
independence stays open here until the held object's own certificate is replayed.
The accountability floor is never closed here either: every answering-duty chain
must end in a natural person, which only a HUMAN certificate can establish and no
adapter issues, so a holder label never stands in for one.
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
            # Every event that changes the holding is declared with its instrument and its
            # position in the order (OWNER-2.1).
            if "instrument" not in obj(event):
                raise Refuted("holding event declared without its instrument")
            obj(event, {"event", "position", "target_limb", "actor_id", "instrument"})
            instrument = obj(event["instrument"], {"id", "issuing_authority"})
            text(instrument["id"])
            text(instrument["issuing_authority"])
            if integer(event["position"]) != idx:
                raise Refuted("events not contiguous in position")
            action = text(event["event"])
            text(event["actor_id"])
            if action == "lapse":
                # A term ending is the clock's doing: it declares nothing and occupies no
                # position, so a lapse declared as an event is malformed (OWNER-2.5).
                raise Refuted("lapse is the clock's doing, not an event, and occupies no position")
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
            elif action == "delegation":
                # A delegation conveys a limb the delegator holds and leaves its own holding
                # intact (OWNER-2.3).
                target = text(event["target_limb"])
                if target not in current_limbs:
                    raise Refuted(f"cannot delegate unheld limb: {target}")
            elif action == "revocation":
                target = text(event["target_limb"])
                current_limbs.discard(target)
            else:
                raise Refuted(f"unknown holding lifecycle action: {action}")
        return {"events_replayed": len(events), "frozen": frozen, "sealed": sealed}

    # Check 3: independence (OWNER-3.1)
    elif check == "independence":
        # The holding never changes a verdict the held object's own certificate reaches. The
        # evidence carries a declared status and digest, not that certificate, so nothing here
        # can replay the verdict the holding is meant to leave alone. An inconsistency the
        # declarations show is refuted; consistent declarations leave independence open.
        held_verdict = obj(need(inputs, "held_verdict"), {"status", "computed_digest"})
        same(held_verdict["computed_digest"], held_object_digest, "held object digest altered")
        if text(held_verdict["status"]) not in ("PASS", "FAIL", "UNKNOWN", "REJECTED"):
            raise Refuted("invalid held verdict status")
        raise Unavailable("the held verdict is declared, not replayed: independence needs the held "
                          "object's own certificate, which this evidence does not carry")

    # Check 4: accountability (OWNER-4.5)
    elif check == "accountability":
        # A holder label is a declaration, not evidence. The floor closes only where every
        # answering-duty chain ends in a natural person, reached through holdings to a HUMAN
        # (HUMAN-4.4), and no adapter issues a HUMAN certificate, so nothing this check reads
        # can close it. Malformed evidence is refuted; a closure condition that is not met is
        # UNKNOWN and never FAIL (OWNER-4.6), so a well-formed chain is reported open.
        holdings_chain = [obj(holding, {"id", "holder", "position"})
                          for holding in seq(need(inputs, "holdings_chain"), budget)]
        for holding in holdings_chain:
            text(holding["id"])
            text(holding["holder"])
            integer(holding["position"])
        origin = text(need(artifact, "chain_origin"))
        answering_duties = {text(duty): text(terminal)
                            for duty, terminal in obj(need(inputs, "answering_duties")).items()}
        if holdings_chain[0]["id"] != origin:
            raise Unavailable("holdings chain does not begin at its declared origin, so it is open")
        for duty in limbs:
            if limbs_kind.get(duty) == "discharge_duty" and duty not in answering_duties:
                raise Unavailable(f"discharge duty '{duty}' has no answering duty, so the chain is open")
        raise Unavailable("termination in a natural person needs a HUMAN certificate, which no "
                          "adapter issues; a holder label is a declaration, not evidence")

    raise Unavailable(f"unsupported OWNER check: {check}")
