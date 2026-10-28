"""Create synthetic retained-carrier examples for Verifier Standard (VSTD).

Hypertext Transfer Protocol (HTTP); HTTP Archive (HAR); JavaScript Object
Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256). These examples neither
contact a server nor import a machine-learning framework. They demonstrate
bounded replay of synthetic records, not observation authenticity or complete
domain-tier conformance. Tensor outputs use Python binary64 arithmetic.

From a checkout with Verifier installed (or its src directory on PYTHONPATH):

    python examples/mainstay_admission.py work/mainstay-demo
    vstd certification mainstay-assess work/mainstay-demo/har.evidence.json --request work/mainstay-demo/har.request.json --policy work/mainstay-demo/har.policy.json --json
    vstd certification mainstay-check work/mainstay-demo/har.certificate.json --request work/mainstay-demo/har.request.json --policy work/mainstay-demo/har.policy.json --json

Replace har with model to replay the safetensors example. Generated certificates
pin the installed mechanism and interpreter; regenerate in a new directory after
dependencies change. Existing files are never overwritten.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct

from verifier.domains.common import digest
from verifier.domains.mainstay_certification import (
    build_mainstay_certificate, mainstay_policy, mainstay_request,
)


def _retained(raw: bytes) -> dict:
    return {"sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "base64": base64.b64encode(raw).decode("ascii")}


def _har_evidence() -> dict:
    request = {"method": "GET", "url": "https://example.invalid/health", "httpVersion": "HTTP/1.1",
               "cookies": [], "headers": [], "queryString": [], "headersSize": -1, "bodySize": 0}
    response = {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1", "cookies": [], "headers": [],
                "content": {"size": 2, "mimeType": "text/plain", "text": "ok"}, "redirectURL": "",
                "headersSize": -1, "bodySize": 2}
    entry = {"startedDateTime": "2026-01-01T00:00:00Z", "time": 0, "request": request,
             "response": response, "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0}}
    document = {"log": {"version": "1.2", "creator": {"name": "synthetic Verifier example", "version": "1"},
                        "entries": [entry]}}
    carrier = _retained(json.dumps(document, sort_keys=True).encode("utf-8"))
    artifact = {"mainstay": {"format_id": "har", "version": "1.2", "carrier_digest": carrier["sha256"]},
                "transcript_digest": digest([entry]),
                "mapping": {"layout": {"relation": "entry pairs request and response", "entity": "entry",
                                       "pairs": {"synthetic-request": "entry/0"}}}}
    return {"schema_version": "verifier-mainstay-evidence-1", "object_name": "HARNESS",
            "subject_id": "synthetic-http-transcript", "artifact": artifact,
            "inputs": {"carrier": carrier, "inventory": {"synthetic-request": entry}, "transcript": [entry]}}


def _model_evidence() -> dict:
    header = {"weight": {"dtype": "F32", "shape": [1, 2], "data_offsets": [0, 8]},
              "bias": {"dtype": "F32", "shape": [1], "data_offsets": [8, 12]},
              "__metadata__": {"provenance": "synthetic Verifier example"}}
    encoded = json.dumps(header, sort_keys=True).encode("utf-8")
    carrier = _retained(struct.pack("<Q", len(encoded)) + encoded + struct.pack("<fff", 2.0, 3.0, 1.0))
    # Independent arithmetic oracle: 2*4 + 3*5 + 1 = 24.
    samples = [{"input": [4.0, 5.0], "output": [24.0]}]
    artifact = {"mainstay": {"format_id": "safetensors", "version": "0.5.3", "carrier_digest": carrier["sha256"]},
                "model": {"architecture": {"input_size": 2, "layers": [{"outputs": 1, "activation": "linear"}],
                                             "arithmetic": "python-binary64"},
                          "tensor_map": [{"weight": "weight", "bias": "bias"}], "tolerance": 0.0},
                "samples_digest": digest(samples),
                "mapping": {"schema": {"relation": "tensor-entry declares dtype and shape", "entity": "tensor-entry",
                                       "pairs": {"matrix": "weight", "offset": "bias"}}}}
    return {"schema_version": "verifier-mainstay-evidence-1", "object_name": "MODEL",
            "subject_id": "synthetic-dense-model", "artifact": artifact,
            "inputs": {"carrier": carrier, "samples": samples,
                       "inventory": {"matrix": {"dtype": "F32", "shape": [1, 2], "values": [2.0, 3.0]},
                                     "offset": {"dtype": "F32", "shape": [1], "values": [1.0]}}}}


def build_documents() -> dict[str, dict]:
    """Create exact current-mechanism documents without writing any file."""
    documents = {}
    for name, evidence, mapping in (("har", _har_evidence(), "layout"), ("model", _model_evidence(), "schema")):
        request = mainstay_request(evidence, checks=["binding", mapping, "roundtrip"])
        policy = mainstay_policy(trust_roots=["checker admits only this example's synthetic fixture provenance"])
        certificate = build_mainstay_certificate(request, evidence, policy=policy)
        if certificate["result"]["status"] != "PASS":
            raise RuntimeError(f"{name} synthetic example did not establish its selected checks")
        for suffix, document in (("evidence", evidence), ("request", request),
                                 ("policy", policy), ("certificate", certificate)):
            documents[f"{name}.{suffix}.json"] = document
    return documents


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("output", type=Path, help="Directory for eight new evidence/request/policy/certificate files.")
    args = parser.parse_args(argv)
    documents = build_documents()
    if any((args.output / name).exists() for name in documents):
        parser.error("example destination files already exist; choose a fresh directory")
    args.output.mkdir(parents=True, exist_ok=True)
    for name, document in documents.items():
        with (args.output / name).open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(document, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
        print(f"Wrote {name}", flush=True)
    print("Selected synthetic checks PASS; authenticity and complete domain tiers NOT_ESTABLISHED.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
