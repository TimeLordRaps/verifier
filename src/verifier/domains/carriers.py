"""Bounded retained mainstay carriers for Verifier Standard (VSTD).

Hypertext Transfer Protocol (HTTP); HTTP Archive (HAR); JavaScript Object Notation (JSON);
Secure Hash Algorithm 256-bit (SHA-256); uniform resource locator (URL).
HAR 1.2: https://www.softwareishard.com/blog/har-12-spec/
safetensors format snapshot: https://github.com/huggingface/safetensors/blob/v0.5.3/README.md#format
The safetensors binding version pins that specification snapshot; the wire format
has no version field. Only finite binary32 (F32) and binary64 (F64) tensors are
supported here. These parsers do not establish full native-format conformance,
observation authenticity, application execution, or unrecorded completeness.
Sizes are bytes, HAR durations are milliseconds, and counts are dimensionless.
"""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal
import base64
import hashlib
import struct
from urllib.parse import urlsplit

from verifier.core.certificate import canonical_bytes
from verifier.core.receipt import strict_json_loads
from .common import (Budget, Refuted, Unavailable, close, digest, inspect_structure,
                     integer, materialize, need, number, obj, same, seq, text)
from .numerical import forward, network

MAX_CARRIER_BYTES = 4 * 1024 * 1024
SUPPORTED = {"har": ("1.2",), "safetensors": ("0.5.3",)}


def _json(raw: bytes, budget: Budget, *, bom: bool = False) -> dict:
    try:
        value = strict_json_loads(raw.decode("utf-8-sig" if bom else "utf-8"))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Refuted("invalid carrier JSON: " + str(exc)) from exc
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 32:
            raise Unavailable("carrier nesting bound exhausted")
        budget.tick()
        if isinstance(item, (dict, list)):
            if len(item) > budget.max_items:
                raise Unavailable("carrier item bound exhausted")
            pending.extend((v, depth + 1) for v in (item.values() if isinstance(item, dict) else item))
    return obj(value)


def _string(value: object) -> str:
    if type(value) is not str:
        raise Refuted("carrier text field must be a string")
    return value


def _pairs(value: object, budget: Budget) -> None:
    for pair in seq(value, budget, nonempty=False):
        record = obj(pair)
        _string(need(record, "name"))
        _string(need(record, "value"))


def _har(raw: bytes, budget: Budget) -> dict:
    document = _json(raw, budget, bom=True)
    log = obj(need(document, "log"))
    same(need(log, "version"), "1.2", "HAR carrier version differs from binding")
    creator = obj(need(log, "creator"))
    text(need(creator, "name"))
    text(need(creator, "version"))
    pages = {}
    for page in seq(log.get("pages", []), budget, nonempty=False):
        identifier = text(need(obj(page), "id"))
        if identifier in pages:
            raise Refuted("duplicate HAR page identifier")
        pages[identifier] = page
    entries = seq(need(log, "entries"), budget)
    for entry in entries:
        row = obj(entry)
        if "pageref" in row and text(row["pageref"]) not in pages:
            raise Refuted("HAR entry names no retained page")
        stamp = text(need(row, "startedDateTime"))
        try:
            instant = datetime.fromisoformat(stamp[:-1] + "+00:00" if stamp.endswith("Z") else stamp)
        except ValueError as exc:
            raise Refuted("invalid HAR start timestamp") from exc
        if instant.tzinfo is None:
            raise Refuted("HAR start timestamp requires an offset")
        elapsed = number(need(row, "time"))
        if elapsed < 0:
            raise Refuted("negative HAR duration")
        timings = obj(need(row, "timings"))
        for name in ("send", "wait", "receive"):
            if number(need(timings, name)) < 0:
                raise Refuted("negative required HAR timing")
        total = Decimal(0)
        for name in ("blocked", "dns", "connect", "send", "wait", "receive"):
            if name in timings:
                value = number(timings[name])
                if value < 0 and value != -1:
                    raise Refuted("invalid unavailable HAR timing")
                if value >= 0:
                    total += Decimal(str(timings[name]))
        if total != Decimal(str(row["time"])):
            raise Refuted("HAR elapsed time differs from timing sum")
        if "ssl" in timings:
            secure = number(timings["ssl"])
            if secure < 0 and secure != -1:
                raise Refuted("invalid HAR secure-connection timing")
            if secure >= 0 and ("connect" not in timings or secure > number(timings["connect"])):
                raise Refuted("HAR secure-connection duration exceeds connect")
        obj(need(row, "cache"))
        request, response = obj(need(row, "request")), obj(need(row, "response"))
        text(need(request, "method"))
        request_url = text(need(request, "url"))
        try:
            target = urlsplit(request_url)
            target.port  # Force the standard parser's port validation too.
        except ValueError as exc:
            raise Refuted("invalid HAR request URL") from exc
        if target.scheme not in ("http", "https") or not target.netloc or target.fragment:
            raise Unavailable("HAR importer supports absolute HTTP URLs without fragments")
        integer(need(response, "status"), 0, 999)
        _string(need(response, "statusText"))
        _string(need(response, "redirectURL"))
        for message in (request, response):
            text(need(message, "httpVersion"))
            _pairs(need(message, "headers"), budget)
            _pairs(need(message, "cookies"), budget)
            integer(need(message, "headersSize"), -1)
            integer(need(message, "bodySize"), -1)
        _pairs(need(request, "queryString"), budget)
        content = obj(need(response, "content"))
        integer(need(content, "size"))
        _string(need(content, "mimeType"))
        if "text" in content:
            _string(content["text"])
        if content.get("encoding") not in (None, "base64"):
            raise Unavailable("unsupported HAR response encoding")
        if content.get("encoding") == "base64":
            encoded = _string(need(content, "text"))
            budget.tick(len(encoded))
            try:
                base64.b64decode(encoded, validate=True)
            except ValueError as exc:
                raise Refuted("invalid HAR encoded response body") from exc
    return {"document": document, "inventory": {f"entry/{i}": entry for i, entry in enumerate(entries)},
            "transcript": entries, "scope": "complete retained HAR entry sequence"}


def _tensors(raw: bytes, budget: Budget) -> dict:
    if len(raw) < 9:
        raise Refuted("truncated safetensors header")
    size = struct.unpack("<Q", raw[:8])[0]
    if size < 2 or size > len(raw) - 8 or raw[8:9] != b"{":
        raise Refuted("invalid safetensors header length or prefix")
    if size > MAX_CARRIER_BYTES:
        raise Unavailable("safetensors header byte bound exceeded")
    header = _json(raw[8:8 + size], budget)
    payload = raw[8 + size:]
    inventory, spans, metadata = {}, [], None
    for name, record in header.items():
        text(name)
        if name == "__metadata__":
            if any(type(k) is not str or type(v) is not str for k, v in obj(record).items()):
                raise Refuted("safetensors metadata must map strings to strings")
            metadata = record
            continue
        row = obj(record, {"dtype", "shape", "data_offsets"})
        dtype = text(row["dtype"])
        if dtype not in ("F32", "F64"):
            raise Unavailable("unsupported safetensors dtype: " + dtype)
        count = 1
        shape = seq(row["shape"], budget, nonempty=False)
        for dimension in shape:
            width = integer(dimension)
            if width > budget.max_items or count * width > budget.max_items:
                raise Unavailable("safetensors tensor element bound exceeded")
            count *= width
        offsets = seq(row["data_offsets"], budget)
        if len(offsets) != 2:
            raise Refuted("safetensors offsets require two endpoints")
        start, end = [integer(v) for v in offsets]
        width, code = (4, "f") if dtype == "F32" else (8, "d")
        if end < start or end > len(payload) or end - start != count * width:
            raise Refuted("safetensors tensor size differs from shape and offsets")
        spans.append((start, end))
        budget.tick(count)
        values = list(struct.unpack("<" + code * count, payload[start:end]))
        try:
            for value in values:
                number(value)
        except Refuted as exc:
            raise Unavailable("dense replay requires bounded finite tensor values") from exc
        inventory[name] = {"dtype": dtype, "shape": shape, "values": values}
    if not inventory:
        raise Unavailable("safetensors carrier contains no retained tensors")
    cursor = 0
    for start, end in sorted(spans):
        if start != cursor:
            raise Refuted("safetensors buffer has a hole or overlapping aliases")
        cursor = end
    if cursor != len(payload):
        raise Refuted("safetensors buffer contains unindexed bytes")
    return {"inventory": inventory, "metadata": metadata,
            "scope": "retained finite F32/F64 tensor container"}


def inspect_carrier(format_id: str, version: str, record: dict, budget: Budget) -> dict:
    """Rehash and parse a retained carrier under an explicitly supported contract."""
    if version not in SUPPORTED.get(format_id, ()):
        raise Unavailable("no admitted carrier parser for this format/version")
    encoded = need(obj(record), "base64")
    if type(encoded) is not str:
        raise Refuted("carrier base64 must be a string")
    if len(encoded) > ((MAX_CARRIER_BYTES + 2) // 3) * 4:
        raise Unavailable("carrier byte bound exceeded before decoding")
    if len(encoded) * 3 // 4 > budget.limit - budget.used:
        raise Unavailable("carrier operation bound exhausted before decoding")
    raw = materialize(record, budget)
    if len(raw) > MAX_CARRIER_BYTES:
        raise Unavailable("carrier byte bound exceeded")
    parsed = _har(raw, budget) if format_id == "har" else _tensors(raw, budget)
    return dict(parsed, carrier_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
                format_id=format_id, version=version, bytes=len(raw))


def mapping(parsed: dict, artifact: dict, inputs: dict, check: str, budget: Budget) -> dict:
    supported = {("har", "layout"): ("entry", "entry pairs request and response"),
                 ("safetensors", "schema"): ("tensor-entry", "tensor-entry declares dtype and shape")}
    contract = supported.get((parsed["format_id"], check))
    if contract is None:
        raise Unavailable("no evidence-derived mapping for this format and obligation")
    declared = obj(need(obj(need(artifact, "mapping")), check), {"relation", "entity", "pairs"})
    same([declared["entity"], declared["relation"]], list(contract), "mapping relation or entity differs")
    pairs, retained = obj(declared["pairs"]), obj(need(inputs, "inventory"))
    if not retained:
        raise Unavailable("mapping inventory empty")
    same(sorted(pairs), sorted(retained), "mapping is not total over retained inventory")
    targets = [text(target) for target in pairs.values()]
    if len(set(targets)) != len(targets):
        raise Refuted("mapping aliases two retained items onto one carrier entity")
    same(sorted(targets), sorted(parsed["inventory"]), "mapping does not cover exact parsed inventory")
    for source, target in pairs.items():
        inspect_structure(retained[source], budget)
        same(retained[source], parsed["inventory"][target], "mapped retained content differs from parsed carrier")
    return {"mapped": len(pairs), "distinct_targets": len(targets), "carrier_digest": parsed["carrier_digest"]}


def _encode_tensors(inventory: dict, budget: Budget, *, metadata: dict | None = None) -> bytes:
    payload, header = bytearray(), {}
    if metadata is not None:
        header["__metadata__"] = metadata
    for name in sorted(inventory):
        row = inventory[name]
        code = "f" if row["dtype"] == "F32" else "d"
        chunk = struct.pack("<" + code * len(row["values"]), *row["values"])
        header[name] = {"dtype": row["dtype"], "shape": row["shape"],
                        "data_offsets": [len(payload), len(payload) + len(chunk)]}
        payload.extend(chunk)
    encoded = canonical_bytes(header)
    budget.tick(len(encoded) + len(payload) + 8)
    return struct.pack("<Q", len(encoded)) + encoded + bytes(payload)


def roundtrip(parsed: dict, artifact: dict, inputs: dict, budget: Budget) -> dict:
    """Execute a supported import/export/import and its domain-specific comparison."""
    if parsed["format_id"] == "har":
        exported = canonical_bytes(parsed["document"])
        budget.tick(len(exported))
        restored = _har(exported, budget)
        expected = seq(need(inputs, "transcript"), budget)
        same(restored["transcript"], expected, "HAR reimport differs from retained transcript")
        same(digest(restored["transcript"]), need(artifact, "transcript_digest"), "HAR transcript commitment differs")
        return {"reimported": True, "transcript_digest": digest(expected), "records": len(expected),
                "exported_digest": "sha256:" + hashlib.sha256(exported).hexdigest(),
                "scope": parsed["scope"], "authentication": "NOT_ESTABLISHED"}
    exported = _encode_tensors(parsed["inventory"], budget, metadata=parsed["metadata"])
    restored = _tensors(exported, budget)
    same(restored["inventory"], parsed["inventory"], "tensor reimport changed retained values")
    same(restored["metadata"], parsed["metadata"], "tensor reimport changed retained metadata")
    model = obj(need(artifact, "model"), {"architecture", "tensor_map", "tolerance"})
    tolerance = number(model["tolerance"])
    if not 0 <= tolerance <= 1e-8:
        raise Unavailable("mainstay dense replay supports tolerance from zero through 1e-8")
    weights, used = [], []
    for row in seq(model["tensor_map"], budget):
        obj(row, {"weight", "bias"})
        weight_name, bias_name = text(row["weight"]), text(row["bias"])
        if weight_name not in restored["inventory"] or bias_name not in restored["inventory"]:
            raise Refuted("dense mapping names no retained tensor")
        weight, bias = restored["inventory"][weight_name], restored["inventory"][bias_name]
        if len(weight["shape"]) != 2 or len(bias["shape"]) != 1:
            raise Unavailable("dense replay requires matrix weights and vector biases")
        width = weight["shape"][1]
        if width == 0:
            raise Unavailable("empty dense layer is unsupported")
        weights.append({"weight": [weight["values"][i:i + width] for i in range(0, len(weight["values"]), width)],
                        "bias": bias["values"]})
        used.extend((weight_name, bias_name))
    if len(used) != len(set(used)):
        raise Refuted("dense mapping aliases a retained tensor")
    same(sorted(used), sorted(restored["inventory"]), "dense mapping omits retained tensors")
    net = network(obj(model["architecture"]), weights, budget)
    samples = seq(need(inputs, "samples"), budget)
    same(digest(samples), need(artifact, "samples_digest"), "bound inference samples differ")
    outputs = []
    for sample in samples:
        obj(sample, {"input", "output"})
        actual = forward(net, sample["input"], budget)[0]
        expected = seq(sample["output"], budget)
        if len(actual) != len(expected):
            raise Refuted("inference output shape differs")
        for a, b in zip(actual, expected):
            close(a, b, tolerance, "reimported model output differs")
        outputs.append(actual)
    return {"reimported": True, "outputs_digest": digest(outputs), "samples": len(samples),
            "metadata_digest": digest(restored["metadata"]),
            "exported_digest": "sha256:" + hashlib.sha256(exported).hexdigest(),
            "scope": "finite dense-network outputs after tensor reimport; Python binary64 arithmetic",
            "authentication": "NOT_ESTABLISHED"}
