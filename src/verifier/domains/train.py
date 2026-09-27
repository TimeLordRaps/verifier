"""Training run specification (TRAIN): checkpoint and numerical replay."""
from __future__ import annotations

from .common import Budget, Refuted, Unavailable, close, digest, integer, need, number, obj, same, seq
from .numerical import configuration, flatten, loss_gradient, network, update, vector


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget) -> dict:
    config = obj(need(artifact, "configuration"))
    configuration(config)
    if check == "configuration":
        return {"optimizer": config["optimizer"], "arithmetic": config["arithmetic"]}
    checkpoints = seq(need(inputs, "checkpoints"), budget)
    commitments = seq(need(artifact, "checkpoint_digests"), budget)
    same([digest(c) for c in checkpoints], commitments, "checkpoint bytes differ")
    architecture = obj(need(artifact, "architecture"))
    for checkpoint in checkpoints:
        obj(checkpoint, {"weights", "optimizer_state"})
        network(architecture, checkpoint["weights"], budget)
        obj(checkpoint["optimizer_state"], {"step", "first", "second"})
    if check == "checkpoints":
        return {"checkpoints": len(checkpoints)}
    steps = seq(need(inputs, "steps"), budget)
    same(digest(steps), need(artifact, "steps_digest"), "training trace differs")
    if len(checkpoints) != len(steps)+1:
        raise Refuted("checkpoint trajectory is incomplete")
    start = integer(need(artifact, "start_step"))
    batches = obj(need(inputs, "batches"))
    used = set()
    tolerance = number(need(artifact, "tolerance"))
    if tolerance < 0:
        raise Refuted("negative numerical tolerance")
    for i, step in enumerate(steps):
        obj(step, {"index", "parent", "result", "configuration_digest", "batch", "gradients", "loss"})
        same(step["index"], start+i, "noncontiguous training step")
        same(step["parent"], commitments[i], "checkpoint parent differs")
        same(step["result"], commitments[i+1], "checkpoint result differs")
        same(step["configuration_digest"], digest(config), "hyperparameters substituted")
        before, after = checkpoints[i], checkpoints[i+1]
        same(before["optimizer_state"]["step"], start+i, "optimizer step differs")
        same(after["optimizer_state"]["step"], start+i+1, "optimizer result step differs")
        batch = need(batches, step["batch"])
        same(digest(batch), step["batch"], "batch digest differs")
        used.add(step["batch"])
        gradients = vector(step["gradients"], budget)
        if check == "training":
            microbatches = seq(batch, budget)
            if len(microbatches) != config["accumulation"]:
                raise Refuted("gradient accumulation differs")
            # Equal-sized microbatches make averaging identical to the full batch mean.
            sizes = [len(seq(b, budget)) for b in microbatches]
            if len(set(sizes)) != 1:
                raise Unavailable("unequal-sized microbatch accumulation unsupported")
            measured = [loss_gradient(architecture, before["weights"], b, budget) for b in microbatches]
            expected_loss = sum(v[0] for v in measured)/len(measured)
            expected_gradient = [sum(v[1][j] for v in measured)/len(measured) for j in range(len(measured[0][1]))]
            close(expected_loss, step["loss"], tolerance, "recomputed training loss differs")
            if len(expected_gradient) != len(gradients):
                raise Refuted("gradient shape differs")
            for actual, expected in zip(expected_gradient, gradients):
                close(actual, expected, tolerance, "recomputed gradient differs")
        if check in ("updates", "training"):
            weights, state = update(before["weights"], gradients, before["optimizer_state"], config, budget)
            for actual, expected in zip(flatten(weights), flatten(after["weights"])):
                close(actual, expected, tolerance, "optimizer update differs")
            for field in ("first", "second"):
                actual, expected = state[field], vector(after["optimizer_state"][field], budget)
                if len(actual) != len(expected):
                    raise Refuted("optimizer state shape differs")
                for a,b in zip(actual, expected):
                    close(a,b,tolerance,"recomputed optimizer state differs")
    same(sorted(used), sorted(batches), "unreferenced batch evidence")
    return {"steps": len(steps), "start_step": start}
