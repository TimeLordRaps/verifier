"""Build deterministic Verifier Standard (VSTD) formation-receipt specimens.

JavaScript Object Notation (JSON) and uniform resource locator (URL)-safe base64
retain synthetic exact inputs. Native outputs are reference observations, not
independent correctness, execution, source derivation or agency evidence.
"""

from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Sequence

from verifier.interoperability.formation_receipt import (
    SELECTION_SCHEMA, build_formation_receipt, decode_formation_receipt,
)
from verifier.interoperability.formation_wire import profile_digest
from verifier.interoperability.network import canonical_bytes, digest_bytes

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/fixtures/formation-interoperability-corpus.json"
TARGET = ROOT / "tests/fixtures/formation-receipt-corpus.json"
MAX_CORPUS_BYTES = 1048576


def encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def build_corpus() -> bytes:
    source_bytes = SOURCE.read_bytes()
    source = json.loads(source_bytes)
    cases: list[dict[str, Any]] = []

    def add(name: str, commit: bytes, evidence: dict[str, bytes], paths: dict[str, str]) -> None:
        selection = canonical_bytes({"schema_version": SELECTION_SCHEMA,
                                     "commit_digest": digest_bytes(commit), **paths})
        data = build_formation_receipt(selection, commit, evidence)
        cases.append({"case_id": name, "selection_bytes_base64url": encode(selection),
                      "commit_bytes_base64url": encode(commit),
                      "evidence": [{"digest": key, "bytes_base64url": encode(value)}
                                   for key, value in sorted(evidence.items())],
                      "receipt_bytes_base64url": encode(data), "receipt_digest": digest_bytes(data),
                      "expected_inspection": decode_formation_receipt(data)["inspection"]})

    for case in source["silo_cases"]:
        add(case["case_id"], decode(case["commit_bytes_base64url"]),
            {item["digest"]: decode(item["bytes_base64url"]) for item in case["evidence"]}, case["paths"])

    base = next(case for case in source["silo_cases"] if case["case_id"] == "silo-valid")
    base_commit = json.loads(decode(base["commit_bytes_base64url"]))
    base_evidence = {item["digest"]: decode(item["bytes_base64url"]) for item in base["evidence"]}
    subject_record = next(item["object"] for item in base_commit["census"] if item["path"] == base["paths"]["subject_path"])
    context = json.loads(base_evidence[subject_record["object_digest"]])["context"]
    pure_names = {"composition", "identity-composition", "quoted-path", "read-path", "nested-quotation",
                  "nested-read", "wrong-application-target", "unused-invalid-node", "dependency-depth-limit"}
    for pure in source["pure_cases"]:
        if pure["case_id"] not in pure_names:
            continue
        subject = json.loads(decode(pure["subject_bytes_base64url"]))
        subject["context"] = deepcopy(context)
        subject_bytes = canonical_bytes(subject)
        certificate = json.loads(decode(pure["certificate_bytes_base64url"]))
        certificate["subject_digest"] = digest_bytes(subject_bytes)
        commit = deepcopy(base_commit)
        evidence = dict(base_evidence)
        for role, payload in (("subject", subject_bytes), ("certificate", canonical_bytes(certificate))):
            record = next(item["object"] for item in commit["census"] if item["path"] == base["paths"][role + "_path"])
            evidence.pop(record["object_digest"], None)
            record["object_digest"] = digest_bytes(payload)
            record["size_bytes"] = len(payload)
            evidence[record["object_digest"]] = payload
        add("formation-" + pure["case_id"], canonical_bytes(commit), evidence, base["paths"])

    for name, commit in (
        ("commit-malformed", b"not json"),
        ("commit-unsupported", b'{"schema_version":"FUTURE-COMMIT"}'),
        ("commit-native-depth-limit", b"[" * 17 + b"0" + b"]" * 17),
        ("commit-native-container-limit", b"[" + b",".join([b"[]"] * 8192) + b"]"),
    ):
        add(name, commit, base_evidence, base["paths"])

    valid = next(case for case in cases if case["case_id"] == "silo-valid")
    foreign = json.loads(decode(valid["receipt_bytes_base64url"]))
    foreign["rule_profile_digest"] = digest_bytes(b"unsupported receipt rule profile")
    mismatch = json.loads(decode(valid["receipt_bytes_base64url"]))
    mismatch["inspection"]["formation_report"]["observation"]["denotation_digest"] = digest_bytes(b"carried false denotation")
    result = canonical_bytes({
        "schema_version": "VSTD-FORMATION-RECEIPT-CORPUS-0.1",
        "source_corpus_digest": digest_bytes(source_bytes), "rule_profile_digest": profile_digest(),
        "cases": cases,
        "recheck_cases": [
            {"case_id": "foreign-receipt-rule-profile", "base_case_id": "silo-valid",
             "receipt_bytes_base64url": encode(canonical_bytes(foreign)),
             "expected_error": "FORMATION_RECEIPT_BINDING_INVALID"},
            {"case_id": "carried-false-denotation", "base_case_id": "silo-valid",
             "receipt_bytes_base64url": encode(canonical_bytes(mismatch)),
             "expected_error": "FORMATION_RECEIPT_NOT_REPRODUCED"},
        ],
    })
    if len(result) > MAX_CORPUS_BYTES:
        raise ValueError("formation receipt corpus exceeds its byte ceiling")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=TARGET)
    args = parser.parse_args(argv)
    data = build_corpus()
    if args.check:
        if not args.output.is_file() or args.output.read_bytes() != data:
            print("FORMATION_RECEIPT_CORPUS_STALE", flush=True)
            return 1
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(data)
    value = json.loads(data)
    print(f"FORMATION_RECEIPT_CORPUS_MATCH cases={len(value['cases'])} recheck_cases={len(value['recheck_cases'])} bytes={len(data)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
