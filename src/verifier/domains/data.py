"""Dataset integrity, lineage and statistics (DATA) over retained records.

JavaScript Object Notation (JSON). Counts and class fractions are dimensionless;
Shannon entropy and its selected absolute tolerance use bits per observation.
Retained statistics establish no external ancestry or population representativeness.
"""
from __future__ import annotations

import math

from verifier.core.certificate import canonical_bytes
from .common import Budget, Refuted, Unavailable, close, digest, integer, merkle_root, need, number, obj, same, seq, text


def inventory(artifact: dict, inputs: dict, budget: Budget) -> dict:
    shards = obj(need(inputs, "shards"))
    commitments = obj(need(artifact, "shards"))
    same(sorted(shards), sorted(commitments), "shard inventory differs")
    if not shards:
        raise Unavailable("no retained shards")
    budget.tick(len(shards))
    for key, commitment in commitments.items():
        records = seq(shards[key], budget, nonempty=False)
        obj(commitment, {"digest", "records", "bytes", "record_digests", "merkle_root"})
        same(digest(records), commitment["digest"], "shard digest differs")
        same(len(records), commitment["records"], "record count differs")
        same(len(canonical_bytes(records)), commitment["bytes"], "byte count differs")
        same([digest(r) for r in records], commitment["record_digests"], "record commitments differ")
        same(merkle_root(records, budget), commitment["merkle_root"], "record digest tree differs")
    return shards


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget) -> dict:
    if type(check) is not str or check not in ("inventory", "schema", "lineage", "splits", "overlap"):
        raise Unavailable("unsupported dataset check")
    shards = inventory(artifact, inputs, budget)
    records = [r for rows in shards.values() for r in rows]
    if check == "schema":
        if "shard_fields" in artifact:
            if "fields" in artifact:
                raise Refuted("choose shared or per-shard schema, not both")
            schemas = obj(artifact["shard_fields"])
            same(sorted(schemas), sorted(shards), "per-shard schema inventory differs")
        else:
            schemas = {key: obj(need(artifact, "fields")) for key in shards}
        types = {"string": str, "integer": int, "number": (int, float), "boolean": bool, "array": list, "object": dict}
        for key, fields in schemas.items():
            if not obj(fields):
                raise Unavailable("record schema absent")
            for kind in fields.values():
                if kind not in types:
                    raise Unavailable("unsupported field type")
            for record in shards[key]:
                budget.tick(len(fields))
                obj(record, set(fields))
                for field, kind in fields.items():
                    expected = types[kind]
                    if type(record[field]) not in (expected if isinstance(expected, tuple) else (expected,)):
                        raise Refuted("record field type differs")
    elif check == "lineage":
        steps = seq(need(artifact, "transforms"), budget)
        available = set(seq(need(artifact, "source_shards"), budget))
        if not available <= set(shards):
            raise Refuted("source shard absent")
        for step in steps:
            obj(step, {"inputs", "output", "operation", "parameters"})
            sources = seq(step["inputs"], budget)
            output = text(step["output"])
            if not set(sources) <= available or output in available or output not in shards:
                raise Refuted("lineage is cyclic, incomplete or overwrites a shard")
            rows = [r for key in sources for r in shards[key]]
            budget.tick(len(rows))
            params = obj(step["parameters"])
            operation = step["operation"]
            if operation == "concat":
                obj(params, set())
            elif operation == "project":
                obj(params, {"fields"})
                fields = seq(params["fields"], budget)
                rows = [{k: need(obj(r), k) for k in fields} for r in rows]
            elif operation == "filter_eq":
                obj(params, {"field", "value"})
                rows = [r for r in rows if canonical_bytes(need(obj(r), params["field"])) == canonical_bytes(params["value"])]
            elif operation == "deduplicate":
                obj(params, set())
                seen = set()
                retained = []
                for row in rows:
                    key = digest(row)
                    if key not in seen:
                        retained.append(row)
                        seen.add(key)
                rows = retained
            else:
                raise Unavailable("unsupported retained-data transformation")
            same(rows, shards[output], "recomputed transformation differs")
            available.add(output)
        same(sorted(available), sorted(shards), "lineage omits retained shards")
    elif check in ("splits", "overlap"):
        splits = obj(need(artifact, "splits"))
        final = seq(need(artifact, "final_shards"), budget)
        if len(final) != len(set(final)):
            raise Refuted("duplicate final shard")
        members = [s for group in splits.values() for s in seq(group, budget)]
        if len(members) != len(set(members)) or set(members) != set(final) or not set(final) <= set(shards):
            raise Refuted("split membership is incomplete or duplicated")
        identity = text(need(artifact, "identity_field"))
        owner = {}
        for split, keys in splits.items():
            for key in keys:
                for record in shards[key]:
                    budget.tick()
                    identifier = digest(need(obj(record), identity))
                    if identifier in owner and owner[identifier] != split:
                        raise Refuted("record identity crosses split boundary")
                    owner[identifier] = split
        if check == "overlap":
            contract = obj(need(artifact, "overlap"), {"train", "evaluation", "text_field", "ngram", "max_overlap"})
            train, evaluation = contract["train"], contract["evaluation"]
            if train == evaluation or train not in splits or evaluation not in splits:
                raise Refuted("distinct retained training and evaluation splits required")
            n = integer(contract["ngram"], 1, 32)
            from .common import number
            threshold = number(contract["max_overlap"])
            if not 0 <= threshold < 1:
                raise Refuted("overlap ceiling must be in [0,1)")
            def texts(split: str) -> list[str]:
                return [text(need(obj(r), contract["text_field"])).strip() for k in splits[split] for r in shards[k]]
            training, testing = texts(train), texts(evaluation)
            if not training or not testing:
                raise Unavailable("empty train/evaluation inventory")
            def grams(value: str) -> set:
                tokens = value.lower().split()
                budget.tick(len(tokens))
                return {tuple(tokens[i:i+n]) for i in range(max(0, len(tokens)-n+1))}
            for left in training:
                a = grams(left)
                for right in testing:
                    budget.tick()
                    b = grams(right)
                    overlap = len(a & b) / len(a | b) if a or b else 0.0
                    if left == right or overlap > threshold:
                        raise Refuted("retained training/evaluation text overlap exceeds bound")
    return {"shards": len(shards), "records": len(records)}


def distribution(artifact: dict, inputs: dict, budget: Budget, *,
                 entropy_tolerance_bits: float) -> dict:
    """Rehash every selected shard and count canonical values without label aliases."""
    tolerance = number(entropy_tolerance_bits)
    if not 0 <= tolerance <= 1e-9:
        raise Refuted("unsupported entropy tolerance in bits")
    shards = inventory(artifact, inputs, budget)
    records = [row for key in sorted(shards) for row in shards[key]]
    if not records:
        raise Unavailable("no retained records to describe")
    declared = obj(need(artifact, "distribution"))
    if not declared:
        raise Unavailable("no selected distribution fields")
    if len(declared) > budget.max_items:
        raise Unavailable("distribution field bound exhausted")
    observed = {}
    for field in sorted(declared):
        text(field)
        summary = obj(declared[field], {"cardinality", "classes", "entropy_bits"})
        counts: dict[bytes, int] = {}
        values = {}
        budget.tick(len(records))
        for row in records:
            if field not in obj(row):
                raise Refuted("selected field absent from a retained record")
            key = canonical_bytes(row[field])
            counts[key] = counts.get(key, 0) + 1
            values[key] = row[field]
        same(len(counts), integer(summary["cardinality"]), "recomputed cardinality differs")
        declared_counts = {}
        for entry in seq(summary["classes"], budget, nonempty=False):
            entry = obj(entry, {"value", "count"})
            key = canonical_bytes(entry["value"])
            if key in declared_counts:
                raise Refuted("duplicate declared distribution class")
            declared_counts[key] = integer(entry["count"], 1)
        if declared_counts != counts:
            raise Refuted("recomputed exact class inventory or count differs")
        total = len(records)
        entropy = math.fsum(-(count / total) * math.log2(count / total)
                            for _, count in sorted(counts.items()))
        close(entropy, summary["entropy_bits"], tolerance, "recomputed entropy differs")
        observed[field] = {
            "cardinality": len(counts), "entropy_bits": entropy,
            "classes": [{"value": values[key], "count": count,
                         "balance_numerator": count, "balance_denominator": total}
                        for key, count in sorted(counts.items())],
        }
    return {"fields": observed, "records": len(records)}
