"""Situated agent (BOT): the closed loop between one agent and one simulation.

BOT establishes the correspondence its parts cannot check separately: that what the
agent retained as an observation is the simulation's own projection of its own state,
and that what the simulation replayed as an action is the agent's own invocation. It
adds no assurance to the certificates it binds. An unbound agent and simulation
establish nothing about the loop between them, however well each replays alone.
"""
from __future__ import annotations

from .common import (Budget, Refuted, Unavailable, bind_certificate, digest, need, obj,
                     same, seq, text)

SEPARATIONS = ("distinct", "fused")


def parts(artifact: dict, inputs: dict, mechanism_digest: str) -> dict:
    """Re-derive every bound certificate; the harness arrives through the agent, not beside it."""
    agent = bind_certificate(inputs, artifact, "agent", "AGENT", mechanism_digest, 5)
    world = bind_certificate(inputs, artifact, "sim", "SIM", mechanism_digest, 4)
    agent_env = bind_certificate(inputs, artifact, "agent_environment", "ENV", mechanism_digest, 2)
    world_env = bind_certificate(inputs, artifact, "sim_environment", "ENV", mechanism_digest, 2)
    certificate = obj(need(agent["inputs"], "harness_certificate"))
    body = {k: v for k, v in certificate.items() if k != "certificate_digest"}
    same(digest(body), need(certificate, "certificate_digest"), "bound harness certificate digest differs")
    same(digest(certificate), need(agent["artifact"], "harness_certificate_digest"),
         "agent certificate does not bind the harness it retained")
    harness = obj(certificate["evidence"])
    ceiling = {text(c) for c in seq(need(agent["artifact"], "required_channels"), Budget(1024, 1024))}
    return {"agent": agent, "world": world, "agent_env": agent_env, "world_env": world_env,
            "harness": harness, "ceiling": ceiling}


def alignment(artifact: dict, bound: dict, budget: Budget) -> dict:
    """Bind each simulation transition to one retained record; an unattributed one is declared."""
    entropy = seq(need(bound["world"]["inputs"], "entropy"), budget, nonempty=False)
    records = seq(need(bound["harness"]["inputs"], "records"), budget)
    step_map = seq(need(artifact, "step_map"), budget, nonempty=False)
    exogenous = seq(artifact.get("exogenous_transitions", []), budget, nonempty=False)
    for index in exogenous:
        if type(index) is not int or not 0 <= index < len(entropy):
            raise Refuted("declared exogenous transition names no simulation transition")
    named = set(exogenous)
    if len(named) != len(exogenous):
        raise Refuted("duplicate exogenous transition")
    attributed = [i for i in range(len(entropy)) if i not in named]
    if len(step_map) != len(attributed):
        raise Refuted("step map does not cover every transition the agent is answerable for")
    previous = -1
    for index in step_map:
        if type(index) is not int or not 0 <= index < len(records):
            raise Refuted("step map names no retained record")
        if index <= previous:
            raise Refuted("step map is not strictly increasing")
        if text(records[index]["channel"]) not in bound["ceiling"]:
            raise Unavailable("the loop was driven on a channel outside the agent's observation ceiling")
        previous = index
    return {"records": records, "step_map": step_map, "attributed": attributed,
            "exogenous": sorted(named)}


def invocations(bound: dict, budget: Budget) -> dict:
    retained = seq(need(bound["harness"]["inputs"], "invocations"), budget, nonempty=False)
    return {i["index"]: i for i in retained if isinstance(i, dict) and type(i.get("index")) is int}


def loop(check: str, artifact: dict, bound: dict, aligned: dict, budget: Budget) -> None:
    """Compare the agent's retained interaction with the simulation's own replay of it."""
    world = bound["world"]["inputs"]
    observations = seq(need(world, "observations"), budget)
    retained = invocations(bound, budget)
    if check == "observation":
        initial = need(artifact, "initial_observation_record")
        if type(initial) is not int or not 0 <= initial < len(aligned["records"]):
            raise Refuted("initial observation names no retained record")
        same(aligned["records"][initial]["payload"], observations[0],
             "retained initial observation differs from the simulation projection")
    actions = seq(need(world, "actions"), budget) if check == "actuation" else []
    for transition, index in zip(aligned["attributed"], aligned["step_map"]):
        budget.tick()
        invocation = retained.get(index)
        if invocation is None:
            raise Refuted("aligned record is not a retained invocation on the world")
        if check == "observation":
            same(invocation["output"], observations[transition + 1],
                 "retained observation differs from the simulation projection of that state")
        else:
            same(invocation["input"], actions[transition],
                 "the simulation replayed an action the agent did not invoke")


def containment(artifact: dict, bound: dict) -> str:
    """Check the declared separation of the two retained environments; fused is not established."""
    separation = text(need(artifact, "separation"))
    if separation not in SEPARATIONS:
        raise Refuted("environment separation must be distinct or fused")
    if separation == "fused":
        raise Unavailable("environment separation declared fused; the agent's runtime is the simulator's")
    agent_env, world_env = bound["agent_env"], bound["world_env"]
    if agent_env["subject_id"] == world_env["subject_id"]:
        raise Refuted("separation declared distinct but both environments name one subject")
    if digest(need(agent_env["artifact"], "files")) == digest(need(world_env["artifact"], "files")):
        raise Refuted("separation declared distinct but both environments retain one software inventory")
    shared = set(seq(need(agent_env["artifact"], "execution_ids"), Budget(4096, 4096))) & \
        set(seq(need(world_env["artifact"], "execution_ids"), Budget(4096, 4096)))
    if shared:
        raise Refuted("one execution is claimed as both the agent runtime and the simulator runtime")
    return separation


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget, *, mechanism_digest: str) -> dict:
    bound = parts(artifact, inputs, mechanism_digest)
    aligned = {"attributed": [], "exogenous": []}
    if check in ("alignment", "observation", "actuation"):
        aligned = alignment(artifact, bound, budget)
        if check != "alignment":
            loop(check, artifact, bound, aligned, budget)
    separation = containment(artifact, bound) if check == "containment" else None
    return {"attributed_transitions": len(aligned["attributed"]),
            "exogenous_transitions": aligned["exogenous"],
            "observation_ceiling": sorted(bound["ceiling"]),
            "environment_separation": separation or "NOT_ESTABLISHED"}
