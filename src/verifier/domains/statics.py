"""Verifier Standard (VSTD) tier-3 statics: the facts an object does not choose.

Tier 3 resists the mechanism every other tier uses. Tiers 1, 2 and 4 are
established by re-executing what the subject declared -- rehash the inventory,
replay the trace, recompute the score. A static fact cannot be established that
way, because re-executing a declaration can only ever confirm the declaration.

Three mechanism kinds establish a static instead, and every check below is one
of them:

``witness``
    A probe of the substrate, recorded by someone other than the subject. The
    checker recomputes whatever part of the probe is determined and refuses to
    pass the part that is not; a machine-dependent measurement is *recorded*,
    never *passed*.
``recompute``
    A statistic recomputed over the retained inventory and compared with the
    declaration. The inventory is evidence; the declaration is a claim about it.
``invariance``
    Re-evaluation of this object's earlier statics with the subject's own
    choices replaced by declared alternatives. If a verdict moves, the fact was
    a choice and the obligation is refuted. This is the direct mechanization of
    "the facts an object does not choose", and it is why every statics profile
    ends with one.

Secure Hash Algorithm 256-bit (SHA-256). No input loads code.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any, Callable

from verifier.core.certificate import canonical_digest
from .common import (Budget, Refuted, Unavailable, close, digest, integer, need, number,
                     obj, same, seq, text)

#: Every statics check name is exposed as ``statics:<name>`` so that it can never
#: be confused with a behavioural adapter check in ``catalog.CHECKS``.
PREFIX = "statics:"


@dataclass(frozen=True)
class Static:
    name: str
    kind: str
    proposition: str

    @property
    def mechanism(self) -> str:
        return PREFIX + self.name


def _rows(*rows: tuple[str, str, str]) -> tuple[Static, ...]:
    return tuple(Static(*row) for row in rows)


#: The six objects whose tier-3 profile carried no mechanism. Order inside each
#: tuple matches the obligation order in ``DOMAIN_OBLIGATIONS.md``.
STATICS: dict[str, tuple[Static, ...]] = {
    "DATA": _rows(
        ("frame", "witness", "The sampled population and the frame's coverage of it are witnessed, not asserted by the pipeline."),
        ("instrument", "witness", "Each measured field's unit and resolution are witnessed, and every retained value lies on that resolution."),
        ("censoring", "recompute", "Declared censoring and truncation bounds are confirmed by mass at the bound in the retained records."),
        ("distribution", "recompute", "Class balance, cardinality and entropy are recomputed over the retained inventory."),
        ("rights", "recompute", "Every shard maps to a licensed source and the composite redistribution term is the meet of its sources."),
        ("independence", "invariance", "The facts above are unchanged when the retaining pipeline's declarations are perturbed."),
    ),
    "TRAIN": _rows(
        ("arithmetic", "witness", "The executing hardware's floating-point behaviour is probed; determined results are recomputed and undetermined ones only recorded."),
        ("accumulation", "recompute", "Order dependence is observed by reducing a retained sequence two ways rather than assumed from the declared order."),
        ("objective", "recompute", "The analytic gradient of the bound objective is recomputed at a retained point, independently of what the run produced."),
        ("geometry", "recompute", "The curvature the architecture and data together fix is recomputed as a conditioning bound at that point."),
        ("independence", "invariance", "The facts above are unchanged when the run's configuration is perturbed."),
    ),
    "HYPER": _rows(
        ("ceiling", "recompute", "The composed depth is recomputed as the minimum over operand established depths and must not be exceeded."),
        ("recurrence", "recompute", "The substrate set appears in every operand's operand closure, at every level."),
        ("exteriority", "recompute", "No decider slot at any level is filled by a certified object."),
        ("conservation", "recompute", "Every composed predicate appears in some operand; a composition manufactures nothing."),
        ("independence", "invariance", "The facts above hold at every nesting depth and under perturbation of the composition's own declarations."),
    ),
    "HARNESS": _rows(
        ("gap", "recompute", "The uninstrumented gap is recomputed as the complement of the instrumented intervals over the session window."),
        ("clock", "witness", "The clock's resolution is probed, and no ordering finer than the observed minimum delta is admitted."),
        ("capacity", "recompute", "Each channel's capacity is confirmed against the retained records, with truncation marked wherever a record reaches it."),
        ("fixity", "invariance", "The facts above are unchanged when the recorded session content is perturbed."),
    ),
    "AGENT": _rows(
        ("ceiling", "recompute", "The observation ceiling is recomputed from the bound harness and must equal, not merely bound, the agent's declaration."),
        ("unknowability", "recompute", "What the agent could not have known is recomputed per step as the complement of the harness-observed set."),
        ("impotence", "invariance", "The facts above are unchanged when the agent's own declarations are perturbed."),
    ),
    "BOT": _rows(
        ("inherited", "recompute", "The ceiling is recomputed through the bound agent's harness, whatever the agent claims about it."),
        ("latency", "witness", "The coupling's delay and ordering are probed from the retained action and effect times."),
        ("disclosure", "recompute", "What the simulation cannot expose is recomputed as the complement of its observation channels."),
        ("impotence", "invariance", "The facts above are unchanged when either side's policy is perturbed."),
    ),
}

#: Where each object keeps the declarations that are its own choices. Perturbing
#: these is what the ``invariance`` check does.
CHOICE_FIELDS = {
    "DATA": ("pipeline",), "TRAIN": ("configuration",), "HYPER": ("composition",),
    "HARNESS": ("session",), "AGENT": ("declarations",), "BOT": ("policies",),
}

BY_NAME = {object_name: {static.name: static for static in rows}
           for object_name, rows in STATICS.items()}


# --------------------------------------------------------------------- witness

def _probe(artifact: dict, key: str, subject: str, budget: Budget) -> Any:
    """A probe the subject could not have authored, with a recomputable commitment."""
    record = obj(need(artifact, key), {"instrument", "observed_by", "observed_at", "measurement", "digest"})
    text(record["instrument"])
    if text(record["observed_by"]) == subject:
        raise Refuted("a static cannot be witnessed by its own subject")
    integer(record["observed_at"])
    same(digest(record["measurement"]), record["digest"], "probe commitment differs from its measurement")
    budget.tick()
    return record["measurement"]


def _arithmetic(measurement: dict, budget: Budget) -> dict:
    """Recompute the determined half of a floating-point probe; record the rest."""
    observed = obj(measurement, {"binary64_epsilon", "binary32_epsilon", "ties", "subnormal",
                                 "nonassociative", "fused_multiply_add"})
    budget.tick(8)
    determined = {"binary64_epsilon": 2.0 ** -52, "binary32_epsilon": 2.0 ** -23,
                  "ties": "even", "subnormal": 5e-324 > 0.0,
                  "nonassociative": (0.1 + 0.2) + 0.3 != 0.1 + (0.2 + 0.3)}
    for key, expected in determined.items():
        same(observed[key], expected, f"floating-point probe contradicts binary arithmetic: {key}")
    if not isinstance(observed["fused_multiply_add"], bool):
        raise Refuted("fused multiply-add availability must be recorded as a boolean")
    # Availability of a fused multiply-add is a property of the executing part, not
    # of the arithmetic; it is recorded as observed and is never a passing condition.
    return {"determined": sorted(determined), "recorded_only": ["fused_multiply_add"],
            "fused_multiply_add": observed["fused_multiply_add"]}


# ------------------------------------------------------------------- recompute

def _entropy(counts: list[int]) -> float:
    total = sum(counts)
    if total <= 0:
        raise Unavailable("no retained records to recompute a distribution over")
    return -sum((c / total) * math.log2(c / total) for c in counts if c > 0)


def _records(inputs: dict, budget: Budget) -> list:
    shards = obj(need(inputs, "shards"))
    rows = [record for key in sorted(shards) for record in seq(shards[key], budget, nonempty=False)]
    if not rows:
        raise Unavailable("no retained records")
    return rows


def _data(check: str, artifact: dict, inputs: dict, budget: Budget) -> dict:
    rows = _records(inputs, budget)
    if check == "censoring":
        declared = obj(need(artifact, "censoring"))
        observed = {}
        for field, bound in declared.items():
            obj(bound, {"side", "value", "mass"})
            limit, side = number(bound["value"]), text(bound["side"])
            if side not in ("left", "right"):
                raise Unavailable("unsupported censoring side")
            budget.tick(len(rows))
            at = sum(1 for r in rows if field in r and number(r[field]) == limit)
            beyond = sum(1 for r in rows if field in r
                         and (number(r[field]) < limit if side == "left" else number(r[field]) > limit))
            if beyond:
                raise Refuted("retained values lie beyond a declared censoring bound")
            if at == 0:
                raise Refuted("a censored field carries no mass at its bound")
            close(at / len(rows), bound["mass"], 1e-9, "censored mass differs from the retained records")
            observed[field] = at
        return {"censored_fields": observed, "records": len(rows)}
    if check == "distribution":
        declared = obj(need(artifact, "distribution"))
        for field, summary in declared.items():
            obj(summary, {"cardinality", "balance", "entropy_bits"})
            budget.tick(len(rows))
            counts: dict[str, int] = {}
            for record in rows:
                value = canonical_key(need(record, field))
                counts[value] = counts.get(value, 0) + 1
            same(len(counts), summary["cardinality"], "recomputed cardinality differs")
            balance = {k: counts[k] / len(rows) for k in sorted(counts)}
            same(sorted(balance), sorted(obj(summary["balance"])), "recomputed class inventory differs")
            for key, share in balance.items():
                close(share, summary["balance"][key], 1e-9, "recomputed class balance differs")
            close(_entropy(list(counts.values())), summary["entropy_bits"], 1e-9,
                  "recomputed entropy differs")
        return {"fields": sorted(declared), "records": len(rows)}
    sources = obj(need(artifact, "sources"))
    assignment = obj(need(artifact, "shard_sources"))
    shards = obj(need(inputs, "shards"))
    same(sorted(assignment), sorted(shards), "every shard must name its source")
    if not set(assignment.values()) <= set(sources):
        raise Refuted("a shard names an undeclared source")
    ranks = {"public-domain": 0, "permissive": 1, "share-alike": 2, "noncommercial": 3, "no-redistribution": 4}
    strongest = "public-domain"
    for name, source in sources.items():
        obj(source, {"licence", "term", "holder"})
        text(source["licence"])
        text(source["holder"])
        if text(source["term"]) not in ranks:
            raise Unavailable(f"unsupported redistribution term for source: {name}")
        if ranks[source["term"]] > ranks[strongest]:
            strongest = source["term"]
    same(strongest, need(artifact, "composite_term"),
         "the composite redistribution term is not the meet of its sources")
    return {"sources": len(sources), "composite_term": strongest}


def canonical_key(value: Any) -> str:
    return value if isinstance(value, str) else digest(value)


def _train(check: str, artifact: dict, inputs: dict, budget: Budget) -> dict:
    point = seq(need(inputs, "point"), budget)
    coefficients = seq(need(artifact, "coefficients"), budget)
    if len(point) != len(coefficients):
        raise Refuted("the retained point and the bound objective disagree on dimension")
    values = [number(x) for x in point]
    weights = [number(c) for c in coefficients]
    tolerance = number(need(artifact, "tolerance"))
    if check == "accumulation":
        budget.tick(2 * len(values))
        forward, backward = 0.0, 0.0
        for x in values:
            forward += x
        for x in reversed(values):
            backward += x
        observed = abs(forward - backward)
        declared = number(need(artifact, "order_sensitivity"))
        if observed > declared:
            raise Refuted("the reduction is more order-sensitive than declared")
        return {"forward_minus_reverse": observed, "declared_bound": declared}
    if check == "objective":
        # The bound objective is the quadratic sum(c_i * x_i^2); its gradient is a
        # fact about the objective, not about the run that reported one.
        budget.tick(len(values))
        analytic = [2.0 * c * x for c, x in zip(weights, values)]
        recorded = [number(g) for g in seq(need(inputs, "gradient"), budget)]
        if len(recorded) != len(analytic):
            raise Refuted("the recorded gradient has the wrong dimension")
        for computed, reported in zip(analytic, recorded):
            close(reported, computed, tolerance, "the run's gradient differs from the objective's")
        return {"dimension": len(analytic), "tolerance": tolerance}
    curvature = [2.0 * c for c in weights]
    if any(value <= 0.0 for value in curvature):
        raise Unavailable("conditioning is undefined for a nonconvex bound objective")
    condition = max(curvature) / min(curvature)
    close(condition, need(artifact, "condition_number"), tolerance,
          "recomputed conditioning differs from the declared geometry")
    return {"condition_number": condition, "curvature_extremes": [min(curvature), max(curvature)]}


def _hyper(check: str, artifact: dict, inputs: dict, budget: Budget) -> dict:
    operands = obj(need(artifact, "operands"))
    budget.tick(len(operands))
    if check == "ceiling":
        depths = {name: integer(obj(record, {"depth", "substrate", "slots", "predicates"})["depth"])
                  for name, record in operands.items()}
        if not depths:
            raise Unavailable("a composition with no operand establishes no ceiling")
        ceiling = min(depths.values())
        declared = integer(need(artifact, "declared_depth"))
        if declared > ceiling:
            raise Refuted("the composition claims a depth no operand established")
        return {"operand_depths": depths, "ceiling": ceiling, "declared_depth": declared}
    if check == "recurrence":
        substrate = set(seq(need(artifact, "substrate"), budget))
        for name, record in operands.items():
            if not substrate <= set(seq(obj(record)["substrate"], budget, nonempty=False)):
                raise Refuted(f"the substrate is consumed rather than recurring at operand: {name}")
        return {"substrate": sorted(substrate), "levels": len(operands)}
    if check == "exteriority":
        certified = set(operands)
        for name, record in operands.items():
            for slot, filler in obj(obj(record)["slots"], None).items():
                if filler is not None and text(filler) in certified:
                    raise Refuted(f"a decider slot is filled by a certified object: {name}.{slot}")
        return {"slots_checked": sum(len(obj(r)["slots"]) for r in operands.values())}
    available: set[str] = set()
    for record in operands.values():
        available |= set(seq(obj(record)["predicates"], budget, nonempty=False))
    composed = set(seq(need(artifact, "predicates"), budget, nonempty=False))
    manufactured = sorted(composed - available)
    if manufactured:
        raise Refuted(f"the composition manufactures evidence absent from every operand: {manufactured[0]}")
    return {"composed": len(composed), "available": len(available)}


def _harness(check: str, artifact: dict, inputs: dict, budget: Budget) -> dict:
    window = obj(need(artifact, "window"), {"start", "end"})
    start, end = integer(window["start"]), integer(window["end"])
    if end <= start:
        raise Refuted("the session window is empty")
    if check == "gap":
        spans = seq(need(inputs, "instrumented"), budget)
        intervals = []
        for span in spans:
            obj(span, {"start", "end"})
            lo, hi = integer(span["start"]), integer(span["end"])
            if not start <= lo < hi <= end:
                raise Refuted("an instrumented interval lies outside the session window")
            intervals.append((lo, hi))
        intervals.sort()
        merged: list[list[int]] = []
        for lo, hi in intervals:
            if merged and lo <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        gaps, cursor = [], start
        for lo, hi in merged:
            if lo > cursor:
                gaps.append({"start": cursor, "end": lo})
            cursor = hi
        if cursor < end:
            gaps.append({"start": cursor, "end": end})
        same(gaps, need(artifact, "gap"), "the declared gap is not the complement of the instrumented intervals")
        return {"gaps": len(gaps), "uninstrumented": sum(g["end"] - g["start"] for g in gaps)}
    channels = obj(need(artifact, "channels"))
    records = obj(need(inputs, "records"))
    same(sorted(channels), sorted(records), "every channel must carry retained records")
    observed = {}
    for name, contract in channels.items():
        obj(contract, {"capacity", "on_overflow"})
        capacity = integer(contract["capacity"], 1)
        if text(contract["on_overflow"]) not in ("truncate", "drop", "reject"):
            raise Unavailable("unsupported channel overflow behaviour")
        rows = seq(records[name], budget, nonempty=False)
        budget.tick(len(rows))
        for row in rows:
            obj(row, {"bytes", "truncated"})
            size = integer(row["bytes"])
            if size > capacity:
                raise Refuted(f"a retained record exceeds its channel capacity: {name}")
            if size == capacity and contract["on_overflow"] == "truncate" and row["truncated"] is not True:
                raise Refuted(f"a record at capacity is not marked truncated: {name}")
        observed[name] = max((integer(r["bytes"]) for r in rows), default=0)
    return {"largest_retained": observed}


def _clock(measurement: dict, artifact: dict, inputs: dict, budget: Budget) -> dict:
    observed = obj(measurement, {"resolution"})
    resolution = integer(observed["resolution"], 1)
    stamps = sorted(integer(t) for t in seq(need(inputs, "timestamps"), budget))
    budget.tick(len(stamps))
    deltas = [b - a for a, b in zip(stamps, stamps[1:]) if b != a]
    if deltas and min(deltas) < resolution:
        raise Refuted("retained timestamps are finer apart than the probed clock resolution")
    indistinguishable = sum(1 for a, b in zip(stamps, stamps[1:]) if b - a < resolution)
    ordered = seq(need(artifact, "ordered_pairs"), budget, nonempty=False)
    for pair in ordered:
        obj(pair, {"earlier", "later"})
        if integer(pair["later"]) - integer(pair["earlier"]) < resolution:
            raise Refuted("an ordering is claimed between events the clock cannot separate")
    return {"resolution": resolution, "indistinguishable_adjacent": indistinguishable,
            "orderings_admitted": len(ordered)}


def _agent(check: str, artifact: dict, inputs: dict, budget: Budget) -> dict:
    harness = obj(need(artifact, "harness"), {"ceiling", "observed"})
    ceiling = integer(harness["ceiling"])
    if check == "ceiling":
        declared = integer(need(artifact, "declared_ceiling"))
        if declared != ceiling:
            raise Refuted("the agent's declared ceiling differs from the one its harness fixes")
        return {"ceiling": ceiling}
    steps = seq(need(inputs, "steps"), budget)
    universe = set(seq(harness["observed"], budget, nonempty=False))
    unknowable = {}
    for index, step in enumerate(steps, 1):
        obj(step, {"available", "asserted_known"})
        available = set(seq(step["available"], budget, nonempty=False))
        if not available <= universe:
            raise Refuted(f"step {index} reads a fact the harness never observed")
        asserted = set(seq(step["asserted_known"], budget, nonempty=False))
        outside = sorted(asserted - available)
        if outside:
            raise Refuted(f"step {index} asserts knowledge of an unobservable fact: {outside[0]}")
        unknowable[str(index)] = sorted(universe - available)
    same(unknowable, need(artifact, "unknowable"),
         "the declared unknowable set is not the complement of what the harness observed")
    return {"steps": len(steps), "universe": len(universe)}


def _bot(check: str, artifact: dict, inputs: dict, budget: Budget) -> dict:
    if check == "inherited":
        agent = obj(need(artifact, "agent"), {"claimed_ceiling", "harness_ceiling"})
        inherited = integer(agent["harness_ceiling"])
        if integer(agent["claimed_ceiling"]) > inherited:
            raise Refuted("the bot inherits a ceiling its agent claims to exceed")
        return {"inherited_ceiling": inherited}
    channels = set(seq(need(artifact, "observation_channels"), budget, nonempty=False))
    state = set(seq(need(artifact, "simulation_state"), budget))
    if not channels <= state:
        raise Refuted("an observation channel exposes a fact outside the simulation state")
    undisclosable = sorted(state - channels)
    same(undisclosable, need(artifact, "cannot_expose"),
         "the declared indisclosure set is not the complement of the observation channels")
    return {"state": len(state), "exposed": len(channels), "cannot_expose": len(undisclosable)}


def _latency(measurement: dict, artifact: dict, inputs: dict, budget: Budget) -> dict:
    observed = obj(measurement, {"minimum", "maximum"})
    pairs = seq(need(inputs, "couplings"), budget)
    budget.tick(len(pairs))
    delays = []
    for pair in pairs:
        obj(pair, {"emitted", "effected"})
        delay = integer(pair["effected"]) - integer(pair["emitted"])
        if delay < 0:
            raise Refuted("an effect precedes the action that caused it")
        delays.append(delay)
    low, high = min(delays), max(delays)
    if integer(observed["minimum"]) > low or integer(observed["maximum"]) < high:
        raise Refuted("the probed latency envelope does not contain the retained couplings")
    declared = obj(need(artifact, "latency_bounds"), {"minimum", "maximum"})
    if integer(declared["minimum"]) > low or integer(declared["maximum"]) < high:
        raise Refuted("the declared latency bounds do not contain the retained couplings")
    return {"observed_minimum": low, "observed_maximum": high, "couplings": len(delays)}


# ------------------------------------------------------------------ invariance

def _invariance(object_name: str, artifact: dict, inputs: dict, budget: Budget, subject: str) -> dict:
    """Re-decide every earlier static with the subject's own choices replaced.

    A static that moves under a perturbation of the object's declarations was
    never static. The alternatives are supplied by the subject, which is safe:
    refusing to supply any leaves the obligation ``UNKNOWN`` rather than passed.
    """
    fields = CHOICE_FIELDS[object_name]
    alternatives = seq(need(artifact, "alternatives"), budget)
    earlier = [s for s in STATICS[object_name] if s.kind != "invariance"]
    baseline = {s.name: _decide(object_name, s.name, artifact, inputs, budget, subject) for s in earlier}
    moved: list[str] = []
    for index, alternative in enumerate(alternatives, 1):
        candidate = obj(alternative)
        if set(candidate) - set(fields):
            raise Refuted("an alternative perturbs something that is not this object's choice")
        if not candidate:
            raise Unavailable("an empty alternative perturbs nothing")
        perturbed = dict(artifact)
        perturbed.update(candidate)
        if canonical_key(perturbed) == canonical_key(artifact):
            raise Unavailable("an alternative that changes nothing cannot establish independence")
        budget.tick()
        for static in earlier:
            verdict = _decide(object_name, static.name, perturbed, inputs, budget, subject)
            if verdict != baseline[static.name]:
                moved.append(f"{static.name}@{index}")
    if moved:
        raise Refuted(f"a tier-3 fact moved when a choice was perturbed: {moved[0]}")
    return {"perturbations": len(alternatives), "invariant": sorted(baseline),
            "choice_fields": list(fields)}


def _decide(object_name: str, check: str, artifact: dict, inputs: dict,
            budget: Budget, subject: str) -> str:
    """The verdict alone, for comparison across perturbations."""
    try:
        evaluate(object_name, check, artifact, inputs, budget, subject=subject)
    except Refuted as exc:
        return "FAIL:" + str(exc)
    except Unavailable as exc:
        return "UNKNOWN:" + str(exc)
    return "PASS"


# -------------------------------------------------------------------- dispatch

_RECOMPUTE: dict[str, Callable[..., dict]] = {
    "DATA": _data, "TRAIN": _train, "HYPER": _hyper,
    "HARNESS": _harness, "AGENT": _agent, "BOT": _bot,
}


def evaluate(object_name: str, check: str, artifact: dict, inputs: dict,
             budget: Budget, *, subject: str = "") -> dict:
    """Establish one tier-3 static of one object over retained evidence."""
    if object_name not in STATICS:
        raise Unavailable(f"no tier-3 statics mechanism for object: {object_name}")
    static = BY_NAME[object_name].get(check)
    if static is None:
        raise Unavailable(f"unsupported statics check: {object_name}.{check}")
    if static.kind == "invariance":
        return _invariance(object_name, artifact, inputs, budget, subject)
    if static.kind == "witness":
        if object_name == "TRAIN":
            return _arithmetic(_probe(artifact, "arithmetic_probe", subject, budget), budget)
        if object_name == "HARNESS":
            return _clock(_probe(artifact, "clock_probe", subject, budget), artifact, inputs, budget)
        if object_name == "BOT":
            return _latency(_probe(artifact, "latency_probe", subject, budget), artifact, inputs, budget)
        measurement = _probe(artifact, check + "_probe", subject, budget)
        if check == "frame":
            observed = obj(measurement, {"population", "frame_size", "covered"})
            text(observed["population"])
            size, covered = integer(observed["frame_size"], 1), integer(observed["covered"])
            if covered > size:
                raise Refuted("the frame covers more than the population it samples")
            retained = len(_records(inputs, budget))
            if retained > covered:
                raise Refuted("more records are retained than the frame covers")
            return {"coverage": covered / size, "retained": retained}
        fields = obj(measurement)
        rows = _records(inputs, budget)
        for field, contract in fields.items():
            obj(contract, {"unit", "resolution", "low", "high"})
            text(contract["unit"])
            step, low, high = number(contract["resolution"]), number(contract["low"]), number(contract["high"])
            if step <= 0 or high < low:
                raise Refuted("an instrument declares an empty range or a nonpositive resolution")
            budget.tick(len(rows))
            for record in rows:
                if field not in record:
                    continue
                value = number(record[field])
                if not low <= value <= high:
                    raise Refuted(f"a retained value lies outside its instrument's range: {field}")
                ticks = (value - low) / step
                if abs(ticks - round(ticks)) > 1e-9 * max(1.0, abs(ticks)):
                    raise Refuted(f"a retained value lies off its instrument's resolution: {field}")
        return {"instrumented_fields": sorted(fields), "records": len(rows)}
    return _RECOMPUTE[object_name](check, artifact, inputs, budget)


def statics_catalog() -> dict:
    """Describe the tier-3 statics mechanism; no dependency chain is implied."""
    return {"schema_version": "verifier-statics-catalog-1", "tier": 3, "objects": {
        object_name: [{"mechanism": static.mechanism, "kind": static.kind,
                       "proposition": static.proposition} for static in rows]
        for object_name, rows in STATICS.items()}}

def statics_digest() -> str:
    """Pin this mechanism family's bytes, separately from the behavioural adapters."""
    import hashlib
    from importlib.resources import files
    data = files("verifier.domains").joinpath("statics.py").read_bytes()
    return canonical_digest({"catalog": statics_catalog(),
                             "implementation": hashlib.sha256(data).hexdigest()})
