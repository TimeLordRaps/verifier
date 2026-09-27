"""Retained mainstay carrier tests for Verifier Standard (VSTD).

Hypertext Transfer Protocol (HTTP); HTTP Archive (HAR); JavaScript Object Notation (JSON).
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct

import pytest

from verifier.domains.common import Budget, Refuted, Unavailable, digest
from verifier.domains.mainstays import evaluate


def retained(raw: bytes) -> dict:
    return {"sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "base64": base64.b64encode(raw).decode()}


def har_document() -> dict:
    request = {"method": "GET", "url": "https://example.invalid/one", "httpVersion": "HTTP/1.1",
               "cookies": [], "headers": [], "queryString": [], "headersSize": -1, "bodySize": 0}
    response = {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1", "cookies": [],
                "headers": [], "content": {"size": 2, "mimeType": "text/plain", "text": "ok"},
                "redirectURL": "", "headersSize": -1, "bodySize": 2}
    entry = {"startedDateTime": "2026-09-26T00:00:00Z", "time": 3,
             "request": request, "response": response, "cache": {},
             "timings": {"send": 1, "wait": 1, "receive": 1}}
    return {"log": {"version": "1.2", "creator": {"name": "fixture", "version": "1"}, "entries": [entry]}}


def har_fixture() -> tuple[dict, dict]:
    doc = har_document()
    raw = json.dumps(doc, indent=2).encode()
    carrier = retained(raw)
    entry = doc["log"]["entries"][0]
    artifact = {"mainstay": {"format_id": "har", "version": "1.2", "carrier_digest": carrier["sha256"]},
                "transcript_digest": digest(doc["log"]["entries"]),
                "mapping": {"layout": {"relation": "entry pairs request and response", "entity": "entry",
                            "pairs": {"retained-entry": "entry/0"}}}}
    inputs = {"carrier": carrier, "inventory": {"retained-entry": entry}, "transcript": doc["log"]["entries"]}
    return artifact, inputs


def tensor_file(header: dict | None = None, payload: bytes | None = None) -> bytes:
    if header is None:
        header = {"weight": {"dtype": "F32", "shape": [1, 2], "data_offsets": [0, 8]},
                  "bias": {"dtype": "F32", "shape": [1], "data_offsets": [8, 12]}}
    encoded = json.dumps(header).encode()
    return struct.pack("<Q", len(encoded)) + encoded + (struct.pack("<fff", 2.0, 3.0, 1.0) if payload is None else payload)


def model_fixture() -> tuple[dict, dict]:
    carrier = retained(tensor_file())
    samples = [{"input": [4.0, 5.0], "output": [24.0]}]
    artifact = {"mainstay": {"format_id": "safetensors", "version": "0.5.3", "carrier_digest": carrier["sha256"]},
                "model": {"architecture": {"input_size": 2, "layers": [{"outputs": 1, "activation": "linear"}],
                                             "arithmetic": "python-binary64"},
                          "tensor_map": [{"weight": "weight", "bias": "bias"}], "tolerance": 0.0},
                "samples_digest": digest(samples),
                "mapping": {"schema": {"relation": "tensor-entry declares dtype and shape", "entity": "tensor-entry",
                            "pairs": {"w": "weight", "b": "bias"}}}}
    inputs = {"carrier": carrier, "samples": samples,
              "inventory": {"w": {"dtype": "F32", "shape": [1, 2], "values": [2.0, 3.0]},
                            "b": {"dtype": "F32", "shape": [1], "values": [1.0]}}}
    return artifact, inputs


def run(domain: str, check: str, artifact: dict, inputs: dict, limit: int = 200000) -> dict:
    return evaluate(domain, check, artifact, inputs, Budget(limit, 4096))


def test_format_label_and_digest_prefix_do_not_bind_a_carrier() -> None:
    artifact, _ = har_fixture()
    with pytest.raises(Unavailable, match="carrier"):
        run("HARNESS", "binding", artifact, {})


def test_declared_equal_roundtrip_strings_do_not_establish_reimport() -> None:
    artifact, _ = har_fixture()
    artifact["round_trip"] = {"exported": "same", "reimported": "same", "loss": []}
    with pytest.raises(Unavailable):
        run("HARNESS", "roundtrip", artifact, {})


@pytest.mark.parametrize("domain,factory", [("HARNESS", har_fixture), ("MODEL", model_fixture)])
def test_supported_carriers_are_rehashed_parsed_and_reimported(domain: str, factory: object) -> None:
    artifact, inputs = factory()
    binding = run(domain, "binding", artifact, inputs)
    assert binding["carrier_digest"] == inputs["carrier"]["sha256"]
    assert binding["native_format_conformance"] == "NOT_ESTABLISHED"
    result = run(domain, "roundtrip", artifact, inputs)
    assert result["reimported"] is True
    assert result["authentication"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("domain,check,factory", [("HARNESS", "layout", har_fixture), ("MODEL", "schema", model_fixture)])
def test_mapping_binds_every_retained_item_to_actual_parsed_content(domain: str, check: str, factory: object) -> None:
    artifact, inputs = factory()
    assert run(domain, check, artifact, inputs)["mapped"] == len(inputs["inventory"])
    key = next(iter(inputs["inventory"]))
    inputs["inventory"][key] = {"substituted": True}
    with pytest.raises(Refuted, match="content"):
        run(domain, check, artifact, inputs)


@pytest.mark.parametrize("mutation", ["digest", "version", "type", "target", "alias", "omission", "sample"])
def test_model_carrier_counterexamples(mutation: str) -> None:
    artifact, inputs = model_fixture()
    check = "binding"
    if mutation == "digest":
        artifact["mainstay"]["carrier_digest"] = "sha256:" + "0" * 64
    elif mutation == "version":
        artifact["mainstay"]["version"] = "unrecognized"
    elif mutation == "type":
        inputs["carrier"]["base64"] = 123
    elif mutation in ("target", "alias", "omission"):
        check = "schema"
        mapping = artifact["mapping"]["schema"]["pairs"]
        if mutation == "target": mapping["w"] = "invented"
        elif mutation == "alias": mapping["w"] = "bias"
        else: del mapping["w"]
    else:
        check = "roundtrip"
        inputs["samples"][0]["output"] = [25.0]
        artifact["samples_digest"] = digest(inputs["samples"])
    expected = Unavailable if mutation == "version" else Refuted
    with pytest.raises(expected):
        run("MODEL", check, artifact, inputs)


@pytest.mark.parametrize("mutation", ["duplicate", "version", "timing", "reference", "request", "transcript"])
def test_har_counterexamples_are_detected_after_rebinding(mutation: str) -> None:
    artifact, inputs = har_fixture()
    doc = har_document()
    entry = doc["log"]["entries"][0]
    if mutation == "version": doc["log"]["version"] = "1.1"
    elif mutation == "timing": entry["time"] = 2
    elif mutation == "reference": entry["pageref"] = "absent"
    elif mutation == "request": entry["request"]["url"] = 1
    elif mutation == "transcript": inputs["transcript"][0]["response"]["status"] = 500
    raw = json.dumps(doc).encode()
    if mutation == "duplicate": raw = raw.replace(b'"version": "1.2"', b'"version": "1.2", "version": "1.2"', 1)
    inputs["carrier"] = retained(raw)
    artifact["mainstay"]["carrier_digest"] = inputs["carrier"]["sha256"]
    with pytest.raises(Refuted):
        run("HARNESS", "roundtrip", artifact, inputs)


@pytest.mark.parametrize("mutation", ["overlap", "hole", "size", "duplicate", "dtype"])
def test_tensor_offsets_shapes_and_duplicate_names_are_bounded(mutation: str) -> None:
    header = {"weight": {"dtype": "F32", "shape": [1, 2], "data_offsets": [0, 8]},
              "bias": {"dtype": "F32", "shape": [1], "data_offsets": [8, 12]}}
    if mutation == "overlap": header["bias"]["data_offsets"] = [4, 8]
    elif mutation == "hole": header["weight"]["data_offsets"] = [1, 9]
    elif mutation == "size": header["weight"]["shape"] = [1000000, 1000000]
    elif mutation == "dtype": header["weight"]["dtype"] = "F16"
    raw = tensor_file(header)
    if mutation == "duplicate":
        encoded = b'{"a":{},"a":{}}'
        raw = struct.pack("<Q", len(encoded)) + encoded
    artifact, inputs = model_fixture()
    inputs["carrier"] = retained(raw)
    artifact["mainstay"]["carrier_digest"] = inputs["carrier"]["sha256"]
    with pytest.raises(Unavailable if mutation in ("size", "dtype") else Refuted):
        run("MODEL", "binding", artifact, inputs)


def test_operation_and_carrier_size_bounds_do_not_expand_from_claims() -> None:
    artifact, inputs = har_fixture()
    with pytest.raises(Unavailable):
        run("HARNESS", "binding", artifact, inputs, limit=8)
    inputs["carrier"]["base64"] = "A" * (6 * 1024 * 1024)
    with pytest.raises(Unavailable, match="byte bound"):
        run("HARNESS", "binding", artifact, inputs, limit=10000000)


def test_registered_but_unsupported_formats_and_semantics_remain_unknown() -> None:
    artifact = {"mainstay": {"format_id": "gymnasium", "version": "1.0.0", "carrier_digest": "sha256:" + "0" * 64}}
    with pytest.raises(Unavailable):
        run("SIM", "binding", artifact, {})
    artifact, inputs = har_fixture()
    with pytest.raises(Unavailable):
        run("HARNESS", "protocol", artifact, inputs)


@pytest.mark.parametrize("domain,format_id,version,raw", [
    ("HARNESS", "har", "1.2", b'{"log":{"version":"1.1"}}'),
    ("MODEL", "safetensors", "0.5.3", b'not a tensor container'),
])
def test_rehashed_malformed_bytes_do_not_bind(domain, format_id, version, raw):
    carrier = retained(raw)
    artifact = {"mainstay": {"format_id": format_id, "version": version, "carrier_digest": carrier["sha256"]}}
    with pytest.raises(Refuted):
        run(domain, "binding", artifact, {"carrier": carrier})


@pytest.mark.parametrize("mutation", ["pageref-type", "url-syntax", "body-encoding"])
def test_malformed_har_fields_return_a_bounded_refutation(mutation):
    artifact, inputs = har_fixture()
    doc = har_document()
    entry = doc["log"]["entries"][0]
    if mutation == "pageref-type":
        entry["pageref"] = []
    elif mutation == "url-syntax":
        entry["request"]["url"] = "https://[not-an-address/"
    else:
        entry["response"]["content"].update(text="!not-base64!", encoding="base64")
    inputs["carrier"] = retained(json.dumps(doc).encode())
    artifact["mainstay"]["carrier_digest"] = inputs["carrier"]["sha256"]
    with pytest.raises(Refuted):
        run("HARNESS", "binding", artifact, inputs)


def test_safetensors_metadata_survives_real_export_and_import():
    from verifier.domains.carriers import _encode_tensors, _tensors
    artifact, inputs = model_fixture()
    header = {"weight": {"dtype": "F32", "shape": [1, 2], "data_offsets": [0, 8]},
              "bias": {"dtype": "F32", "shape": [1], "data_offsets": [8, 12]},
              "__metadata__": {"format": "pt", "author": "retained fixture"}}
    raw = tensor_file(header)
    parsed = _tensors(raw, Budget(200000, 4096))
    assert parsed["metadata"] == header["__metadata__"]
    exported = _encode_tensors(parsed["inventory"], Budget(200000, 4096), metadata=parsed["metadata"])
    assert _tensors(exported, Budget(200000, 4096))["metadata"] == header["__metadata__"]
    inputs["carrier"] = retained(raw)
    artifact["mainstay"]["carrier_digest"] = inputs["carrier"]["sha256"]
    assert run("MODEL", "roundtrip", artifact, inputs)["metadata_digest"] == digest(header["__metadata__"])


def test_binary64_two_layer_reimport_recomputes_a_relu_oracle():
    entries = {"w1": ([2, 2], [1.0, -2.0, 3.0, 4.0]), "b1": ([2], [-1.0, 0.5]),
               "w2": ([1, 2], [0.5, 2.0]), "b2": ([1], [-0.5])}
    header, payload = {}, bytearray()
    for name, (shape, values) in entries.items():
        start = len(payload)
        payload.extend(struct.pack("<" + "d" * len(values), *values))
        header[name] = {"dtype": "F64", "shape": shape, "data_offsets": [start, len(payload)]}
    carrier = retained(tensor_file(header, bytes(payload)))
    samples = [{"input": [2.0, 1.0], "output": [20.5]}]
    artifact = {"mainstay": {"format_id": "safetensors", "version": "0.5.3", "carrier_digest": carrier["sha256"]},
                "model": {"architecture": {"input_size": 2, "layers": [{"outputs": 2, "activation": "relu"},
                                            {"outputs": 1, "activation": "linear"}], "arithmetic": "python-binary64"},
                          "tensor_map": [{"weight": "w1", "bias": "b1"}, {"weight": "w2", "bias": "b2"}],
                          "tolerance": 0.0}, "samples_digest": digest(samples)}
    assert run("MODEL", "roundtrip", artifact, {"carrier": carrier, "samples": samples})["outputs_digest"] == digest([[20.5]])
    samples[0]["output"] = [19.5]
    artifact["samples_digest"] = digest(samples)
    with pytest.raises(Refuted, match="output differs"):
        run("MODEL", "roundtrip", artifact, {"carrier": carrier, "samples": samples})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_native_nonfinite_tensor_values_remain_unsupported(value):
    artifact, inputs = model_fixture()
    inputs["carrier"] = retained(tensor_file(payload=struct.pack("<fff", value, 3.0, 1.0)))
    artifact["mainstay"]["carrier_digest"] = inputs["carrier"]["sha256"]
    with pytest.raises(Unavailable, match="finite"):
        run("MODEL", "roundtrip", artifact, inputs)
