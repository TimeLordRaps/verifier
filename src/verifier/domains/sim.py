"""Generative simulation specification (SIM): finite transition and relation replay.

Ed25519 is the Edwards-curve digital signature algorithm with a 255-bit field.
Signatures bind retained observations to checker-selected keys, not independence.
State variables and causal time have the units of the supplied model contract.
"""
from __future__ import annotations

import base64
from .common import Budget, Refuted, Unavailable, close, digest, expression, need, number, obj, same, seq, text


def transition(program: dict, state: dict, entropy: object, budget: Budget) -> dict:
    same(sorted(program), sorted(state), "transition state inventory differs")
    variables = dict(state)
    if "entropy" in variables:
        raise Refuted("reserved state variable: entropy")
    variables["entropy"] = number(entropy)
    return {key: number(expression(tree, variables, budget)) for key,tree in program.items()}


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget, *, witness_keys: dict) -> dict:
    program = obj(need(artifact, "transition"))
    states = seq(need(inputs, "states"), budget)
    entropy = seq(need(inputs, "entropy"), budget, nonempty=False)
    times = seq(need(inputs, "times"), budget)
    same(digest(states), need(artifact, "trajectory_digest"), "trajectory differs")
    same(digest(entropy), need(artifact, "entropy_digest"), "entropy stream differs")
    same(digest(times), need(artifact, "times_digest"), "causal times differ")
    same(states[0], need(artifact, "initial_state"), "initial state differs")
    if len(states) != len(entropy)+1 or len(times) != len(states) or len(states) < 2:
        raise Refuted("trajectory/entropy/time coverage differs")
    for i,state in enumerate(states):
        obj(state, set(program))
        for value in state.values():
            number(value)
        if i and number(times[i]) <= number(times[i-1]):
            raise Refuted("causal times are not increasing")
    for i, value in enumerate(entropy):
        expected = transition(program, states[i], value, budget)
        same(expected, states[i+1], "transition replay differs")
    if check == "invariants":
        invariants = seq(need(artifact, "invariants"), budget)
        for state in states:
            for invariant in invariants:
                if expression(invariant, state, budget) is not True:
                    raise Refuted("trajectory invariant refuted")
        finite = artifact.get("finite_state_set")
        if finite is not None:
            boundary = seq(finite, budget)
            choices = seq(need(artifact, "finite_entropy_set"), budget)
            identities = {digest(s) for s in boundary}
            if len(identities) != len(boundary) or digest(states[0]) not in identities:
                raise Refuted("finite state boundary duplicated or excludes initial state")
            if any(digest(s) not in identities for s in states) or any(v not in choices for v in entropy):
                raise Refuted("trace outside finite boundary")
            for state in boundary:
                for invariant in invariants:
                    if expression(invariant, obj(state, set(program)), budget) is not True:
                        raise Refuted("enumerated-state invariant refuted")
                for choice in choices:
                    if digest(transition(program, state, choice, budget)) not in identities:
                        raise Refuted("enumerated state set is not transition-closed")
    elif check == "refinement":
        projection = obj(need(artifact, "projection"))
        if not projection:
            raise Unavailable("empty macro projection")
        macro = seq(need(inputs, "macro_states"), budget)
        same(digest(macro), need(artifact, "macro_digest"), "macro trajectory differs")
        if len(macro) != len(states):
            raise Refuted("macro trajectory coverage differs")
        for state, target in zip(states, macro):
            obj(target, set(projection))
            for key, tree in projection.items():
                close(expression(tree, state, budget), target[key], need(artifact, "tolerance"), "macro projection differs")
    elif check == "channels":
        projection = obj(need(artifact, "observation"))
        channels = obj(need(artifact, "action_bounds"))
        if not projection or not channels:
            raise Unavailable("channel contract empty")
        observations = seq(need(inputs, "observations"), budget)
        actions = seq(need(inputs, "actions"), budget)
        if len(observations) != len(states) or len(actions) != len(entropy):
            raise Refuted("channel coverage differs")
        for state, observed in zip(states, observations):
            expected = {key: expression(tree, state, budget) for key,tree in projection.items()}
            same(expected, observed, "observation projection differs")
        for action in actions:
            obj(action, set(channels))
            for key, bounds in channels.items():
                obj(bounds, {"minimum", "maximum"})
                if not number(bounds["minimum"]) <= number(action[key]) <= number(bounds["maximum"]):
                    raise Refuted("retained action outside channel bounds")
    elif check == "shards":
        contract = obj(need(artifact, "shards"), {"ids", "relations", "require_signatures"})
        identifiers = seq(contract["ids"], budget)
        for identifier in identifiers:
            if text(identifier) == "root" or "." in identifier:
                raise Refuted("shard identifier shadows a reserved relation namespace")
        shards = obj(need(inputs, "shards"))
        if len(set(identifiers)) != len(identifiers) or len(identifiers) < 2:
            raise Refuted("at least two distinct shards required")
        same(sorted(shards), sorted(identifiers), "shard coverage differs")
        if type(contract["require_signatures"]) is not bool:
            raise Refuted("signature requirement must be Boolean")
        for key, records in shards.items():
            rows = seq(records, budget)
            if len(rows) != len(states):
                raise Refuted("shard trajectory coverage differs")
            for i, row in enumerate(rows):
                obj(row, {"time", "state", "signature"})
                same(row["time"], times[i], "shard causal time differs")
                state = obj(row["state"])
                for value in state.values():
                    number(value)
                if contract["require_signatures"]:
                    if key not in witness_keys:
                        raise Unavailable("external witness key absent")
                    try:
                        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                        from cryptography.exceptions import InvalidSignature
                    except ImportError as exc:
                        raise Unavailable("signature backend unavailable") from exc
                    from verifier.core.certificate import canonical_bytes
                    message = {"artifact_digest": digest(artifact), "shard": key, "step": i, "time": times[i], "state": state}
                    try:
                        Ed25519PublicKey.from_public_bytes(bytes.fromhex(witness_keys[key])).verify(
                            base64.b64decode(row["signature"], validate=True), canonical_bytes(message))
                    except (ValueError, TypeError, InvalidSignature) as exc:
                        raise Refuted("shard signature does not authenticate its exact coordinate") from exc
                elif row["signature"] is not None:
                    raise Refuted("unrequested signature cannot supply authority")
        relations = seq(contract["relations"], budget)
        for i in range(len(states)):
            variables = {f"root.{k}": v for k,v in states[i].items()}
            for key in identifiers:
                variables.update({f"{key}.{k}": v for k,v in shards[key][i]["state"].items()})
            for relation in relations:
                if expression(relation, variables, budget) is not True:
                    raise Refuted("cross-shard relation refuted")
    return {"states": len(states), "transitions": len(entropy)}
