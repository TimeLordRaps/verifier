"""Model reproducibility specification (MODEL): inference, metrics and finite probes."""
from __future__ import annotations

from .common import Budget, Refuted, Unavailable, close, digest, expression, need, number, obj, same, seq, unique
from .numerical import forward, network, vector


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget) -> dict:
    architecture = obj(need(inputs, "architecture"))
    weights = seq(need(inputs, "weights"), budget)
    same(digest(architecture), need(artifact, "architecture_digest"), "architecture differs")
    same(digest(weights), need(artifact, "weights_digest"), "weights differ")
    dependencies = obj(need(artifact, "dependencies"))
    retained = obj(need(inputs, "dependencies"))
    same(sorted(dependencies), sorted(retained), "dependency inventory differs")
    for key, value in retained.items():
        same(digest(value), dependencies[key], "dependency artifact differs")
    if check == "artifacts":
        return {"dependencies": len(dependencies)}
    net = network(architecture, weights, budget)
    if check == "tensors":
        return {"layers": len(net)}
    tolerance = number(need(artifact, "tolerance"))
    if tolerance < 0:
        raise Refuted("negative numerical tolerance")
    if check in ("inference", "evaluation"):
        samples = unique(seq(need(inputs, "samples"), budget), "id")
        same(digest(list(samples.values())), need(artifact, "samples_digest"), "evaluation set differs")
        squared, absolute, correct, count = 0.0, 0.0, 0, 0
        for sample in samples.values():
            obj(sample, {"id", "input", "target", "output"})
            output, _ = forward(net, sample["input"], budget)
            recorded = vector(sample["output"], budget)
            if len(output) != len(recorded):
                raise Refuted("output shape differs")
            for actual, expected in zip(output, recorded):
                close(actual, expected, tolerance, "recomputed model output differs")
            if check == "evaluation":
                metric = need(artifact, "metric")
                if metric in ("mean_squared_error", "mean_absolute_error"):
                    target = vector(sample["target"], budget)
                    if len(target) != len(output):
                        raise Refuted("evaluation target shape differs")
                    squared += sum((a-b)**2 for a,b in zip(output, target))
                    absolute += sum(abs(a-b) for a,b in zip(output, target))
                    count += len(output)
                elif metric == "accuracy":
                    from .common import integer
                    target = integer(sample["target"], 0, len(output)-1)
                    correct += max(range(len(output)), key=output.__getitem__) == target
                    count += 1
                else:
                    raise Unavailable("unsupported evaluation metric")
        result = {"samples": len(samples)}
        if check == "evaluation":
            measured = {"mean_squared_error": squared, "mean_absolute_error": absolute, "accuracy": correct}[metric]/count
            close(measured, need(inputs, "metric_value"), tolerance, "reported metric differs")
            bounds = obj(need(artifact, "metric_bounds"), {"minimum", "maximum"})
            if not number(bounds["minimum"]) <= measured <= number(bounds["maximum"]):
                raise Refuted("recomputed metric outside contract")
            result["metric_value"] = measured
        return result
    probes = seq(need(artifact, "challenges"), budget)
    unique(probes, "id")
    for probe in probes:
        obj(probe, {"id", "input", "condition"})
        output, _ = forward(net, probe["input"], budget)
        if expression(probe["condition"], {f"output.{i}": v for i,v in enumerate(output)}, budget) is not True:
            raise Refuted("finite model challenge refutes its bound condition")
    return {"challenges": len(probes)}
