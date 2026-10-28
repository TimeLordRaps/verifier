"""Accountable party specification (ACTOR): decisions attributed to accountable parties.

An ACTOR certificate establishes the bound party, its control surface, decision classes,
delegations and the attribution of its decisions. An instrument executes while the actor
answers. Attribution requires independent witnessing: a witness counts only when it signs
the exact decision trace under a key the checker admits and the actor does not control, so
self-attribution alone cannot establish accountability. Non-transferable accountability
(ACTOR-3.2) is not checked here. Counts are dimensionless.
"""
from __future__ import annotations

from verifier.core.signature_keys import admit_ed25519_public_key

import base64
from typing import Any

from verifier.core.certificate import canonical_bytes
from .common import (Budget, Refuted, Unavailable, digest, integer, need, obj, same, seq, text)


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget, *,
             witness_keys: dict[str, str] | None = None, **_: Any) -> dict:
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
        if actor_id in instrument_components:
            # ACTOR-1.1 names the party accountable for decisions, never an instrument.
            raise Refuted("the actor is named as one of its own instruments")
        return {"actor_id": actor_id, "control_keys": len(control_keys),
                "decision_classes": decision_classes, "admitted_spaces": admitted_spaces}

    # Check 2: delegation (ACTOR-2.1)
    elif check == "delegation":
        delegation_events = seq(need(inputs, "delegation_events"), budget, nonempty=False)
        same(digest(delegation_events), need(artifact, "delegations_digest"), "delegation events differ")
        active_delegations: dict[str, list] = {}
        for idx, event in enumerate(delegation_events):
            # ACTOR-2.1: declared as an event at a stated position, to another actor, with the
            # subset and the interval named.
            obj(event, {"event", "position", "delegate", "subset", "interval"})
            if integer(event["position"]) != idx:
                raise Refuted("delegation events are not contiguous in position")
            kind = text(event["event"])
            delegate = text(event["delegate"])
            if delegate == actor_id:
                raise Refuted("a delegation conveys authority to another actor, never to the actor itself")
            interval = seq(event["interval"], budget)
            if len(interval) != 2 or integer(interval[0]) > integer(interval[1]):
                raise Refuted("a delegation names its interval as an ordered start and end")
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

    # Check 3: accountability (ACTOR-3.4)
    elif check == "accountability":
        # An actor cannot be the sole witness of its own accountability: an attribution resting
        # only on a record the actor exclusively controls establishes nothing. A witness
        # identifier is a declaration and shows neither who wrote the record nor who controls
        # it, so a witness counts only when it signs the exact decision trace under a key the
        # checker's own policy admits and the actor's control surface does not contain. That
        # admission is the checker's; the signature proves the key signed, not independence.
        decisions = seq(need(inputs, "decisions"), budget)
        traced = need(artifact, "decisions_digest")
        same(digest(decisions), traced, "decision trace differs")
        decision_ids = [text(need(obj(decision), "decision_id")) for decision in decisions]
        # Control belongs to key material, not the spelling of its hexadecimal encoding.
        try:
            controlled = {bytes.fromhex(text(need(obj(key), "public_key"))) for key in control_surface}
        except ValueError as exc:
            raise Refuted("actor control key must be hex-encoded bytes") from exc
        # Copy the validated caller mapping into a local built-in receiver.  The
        # evaluator never mutates it, and the explicit dict boundary lets the
        # closed-effect audit prove that ``get`` is the pure built-in method.
        admitted = {} if witness_keys is None else dict(obj(witness_keys))
        pending, verified, witnessed = [], 0, set()
        for w in seq(need(inputs, "witness_attributions"), budget):
            obj(w, {"witness_id", "decision_id", "actor_id", "signature"})
            witness_id, decision_id = text(w["witness_id"]), text(w["decision_id"])
            if text(w["actor_id"]) != actor_id:
                raise Refuted("witness attribution binds another actor")
            if decision_id not in decision_ids:
                raise Refuted("witness attests a decision outside the bound decision trace")
            key = admitted.get(witness_id)
            if witness_id != actor_id and key is not None and bytes.fromhex(key) not in controlled:
                pending.append((w, key))
        if pending:
            try:
                pending = [(w, admit_ed25519_public_key(bytes.fromhex(key))) for w, key in pending]
            except (ValueError, TypeError) as exc:
                raise Refuted("witness signing key is inadmissible") from exc
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                from cryptography.exceptions import InvalidSignature
            except ImportError as exc:
                raise Unavailable("signature backend unavailable") from exc
            for w, key in pending:
                budget.tick()
                statement = {"attests": "ACTOR-3.4", "actor_id": actor_id, "decision_id": w["decision_id"],
                             "decisions_digest": traced, "witness_id": w["witness_id"]}
                try:
                    Ed25519PublicKey.from_public_bytes(key).verify(
                        base64.b64decode(text(w["signature"]), validate=True), canonical_bytes(statement))
                except (ValueError, TypeError, InvalidSignature) as exc:
                    raise Refuted("witness signature does not verify over the attested decision") from exc
                verified += 1
                witnessed.add(w["decision_id"])
        for decision_id in decision_ids:
            if decision_id not in witnessed:
                raise Unavailable(f"decision {decision_id} rests on no independent witness the checker admits")
        return {"witnesses_verified": verified, "decisions_witnessed": len(witnessed)}

    # Check 4: attribution (ACTOR-4.2)
    elif check == "attribution":
        decisions = seq(need(inputs, "decisions"), budget)
        same(digest(decisions), need(artifact, "decisions_digest"), "decision trace differs")
        actor_components = {text(c) for c in seq(boundary["actor"], budget)}
        attributed_decisions = set()
        for idx, decision in enumerate(decisions):
            obj(decision, {"decision_id", "position", "decision_class", "actor", "instrument", "timestamp"})
            if integer(decision["position"]) != idx:
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
            if text(decision["instrument"]) in actor_components:
                raise Refuted("instrument is an actor component")
        return {"decisions_attributed": len(attributed_decisions), "unattributed": 0}

    raise Unavailable(f"unsupported ACTOR check: {check}")
