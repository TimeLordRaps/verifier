"""Bounded dense-network arithmetic for retained model and training evidence.

Rectified linear unit (ReLU); stochastic gradient descent (SGD); adaptive moment
estimation (Adam); Adam with decoupled weight decay (AdamW). Calculations use
Python binary64 arithmetic in explicit list order, not accelerator arithmetic.
Loss is mean squared error over samples and outputs; derivatives at ReLU zero
are zero. Values carry the units declared by the user's numerical contract.
"""
from __future__ import annotations

import math
from .common import Budget, Refuted, Unavailable, integer, number, obj, seq


def vector(value: object, budget: Budget) -> list[float]:
    return [number(x) for x in seq(value, budget)]


def network(architecture: dict, weights: list, budget: Budget) -> list:
    obj(architecture, {"input_size", "layers", "arithmetic"})
    if architecture["arithmetic"] != "python-binary64":
        raise Unavailable("unsupported numerical arithmetic")
    width = integer(architecture["input_size"], 1, budget.max_items)
    layers = seq(architecture["layers"], budget)
    if len(seq(weights, budget)) != len(layers):
        raise Refuted("layer inventory differs")
    result = []
    for layer, values in zip(layers, weights):
        obj(layer, {"outputs", "activation"})
        output = integer(layer["outputs"], 1, budget.max_items)
        if layer["activation"] not in ("linear", "relu"):
            raise Unavailable("unsupported dense activation")
        obj(values, {"weight", "bias"})
        matrix = [vector(row, budget) for row in seq(values["weight"], budget)]
        bias = vector(values["bias"], budget)
        if len(matrix) != output or len(bias) != output or any(len(row) != width for row in matrix):
            raise Refuted("dense tensor shape differs")
        result.append((matrix, bias, layer["activation"]))
        width = output
    return result


def forward(net: list, x: list, budget: Budget) -> tuple[list, list]:
    value = vector(x, budget)
    history = []
    for weight, bias, activation in net:
        if len(value) != len(weight[0]):
            raise Refuted("inference input shape differs")
        budget.tick(len(weight)*len(value))
        pre = [number(sum(w*a for w, a in zip(row, value))+b) for row, b in zip(weight, bias)]
        history.append((value, pre))
        value = [max(0.0, a) for a in pre] if activation == "relu" else pre
    return value, history


def flatten(weights: list) -> list[float]:
    return [v for layer in weights for group in (layer["weight"], [layer["bias"]]) for row in group for v in row]


def restore(values: list, weights: list) -> list:
    iterator = iter(values)
    return [{"weight": [[next(iterator) for _ in row] for row in layer["weight"]],
             "bias": [next(iterator) for _ in layer["bias"]]} for layer in weights]


def loss_gradient(architecture: dict, weights: list, batch: list, budget: Budget) -> tuple[float, list]:
    net = network(architecture, weights, budget)
    samples = seq(batch, budget)
    size = len(samples)*len(net[-1][1])
    gradients = [{"weight": [[0.0]*len(row) for row in w], "bias": [0.0]*len(b)} for w,b,_ in net]
    loss = 0.0
    for sample in samples:
        obj(sample, {"input", "target"})
        output, history = forward(net, sample["input"], budget)
        target = vector(sample["target"], budget)
        if len(target) != len(output):
            raise Refuted("training target shape differs")
        loss += sum((a-b)**2 for a,b in zip(output, target))/size
        delta = [2*(a-b)/size for a,b in zip(output, target)]
        for index in range(len(net)-1, -1, -1):
            weight, _, activation = net[index]
            previous, pre = history[index]
            if activation == "relu":
                delta = [d if z > 0 else 0.0 for d,z in zip(delta, pre)]
            budget.tick(len(weight)*len(previous))
            for i,d in enumerate(delta):
                gradients[index]["bias"][i] += d
                for j,a in enumerate(previous):
                    gradients[index]["weight"][i][j] += d*a
            delta = [sum(weight[i][j]*delta[i] for i in range(len(weight))) for j in range(len(previous))]
    return number(loss), [number(v) for v in flatten(gradients)]


def configuration(config: dict) -> None:
    obj(config, {"optimizer", "learning_rate", "weight_decay", "beta1", "beta2", "epsilon",
                 "momentum", "schedule", "accumulation", "max_grad_norm", "arithmetic"})
    if config["optimizer"] not in ("sgd", "adam", "adamw") or config["arithmetic"] != "python-binary64":
        raise Unavailable("unsupported optimizer or arithmetic")
    if config["schedule"] != "constant":
        raise Unavailable("unsupported learning-rate schedule")
    integer(config["accumulation"], 1, 4096)
    for key in ("learning_rate", "epsilon", "max_grad_norm"):
        if number(config[key]) <= 0:
            raise Refuted("optimizer scale must be positive")
    if number(config["weight_decay"]) < 0:
        raise Refuted("weight decay must be nonnegative")
    for key in ("beta1", "beta2", "momentum"):
        if not 0 <= number(config[key]) < 1:
            raise Refuted("optimizer decay outside [0,1)")
    if config["optimizer"] != "sgd" and config["momentum"] != 0:
        raise Refuted("momentum is not an Adam parameter")


def update(weights: list, gradients: list, state: dict, config: dict, budget: Budget) -> tuple[list, dict]:
    configuration(config)
    parameters = [number(v) for v in flatten(weights)]
    grads = vector(gradients, budget)
    obj(state, {"step", "first", "second"})
    step = integer(state["step"])
    first, second = vector(state["first"], budget), vector(state["second"], budget)
    if not len(parameters) == len(grads) == len(first) == len(second):
        raise Refuted("optimizer tensor inventory differs")
    if any(v < 0 for v in second):
        raise Refuted("negative second moment")
    if step == 0 and any(v != 0 for v in first+second):
        raise Refuted("initial optimizer state must be zero")
    norm = math.sqrt(sum(g*g for g in grads))
    scale = min(1.0, config["max_grad_norm"]/norm) if norm else 1.0
    grads = [g*scale for g in grads]
    lr, decay = config["learning_rate"], config["weight_decay"]
    beta1, beta2, eps = config["beta1"], config["beta2"], config["epsilon"]
    result, next_first, next_second = [], [], []
    for p,g,m,v in zip(parameters, grads, first, second):
        budget.tick()
        if config["optimizer"] != "adamw":
            g += decay*p
        if config["optimizer"] == "sgd":
            if v != 0:
                raise Refuted("unused stochastic-gradient second moment must be zero")
            m = config["momentum"]*m+g
            value = p-lr*m
        else:
            m, v = beta1*m+(1-beta1)*g, beta2*v+(1-beta2)*g*g
            base = p*(1-lr*decay) if config["optimizer"] == "adamw" else p
            value = base-lr*(m/(1-beta1**(step+1)))/(math.sqrt(v/(1-beta2**(step+1)))+eps)
        result.append(number(value))
        next_first.append(number(m))
        next_second.append(number(v))
    return restore(result, weights), {"step": step+1, "first": next_first, "second": next_second}
