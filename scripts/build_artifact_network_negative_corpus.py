"""Build the bounded Verifier Standard (VSTD) negative wire corpus.

JavaScript Object Notation (JSON), Secure Hash Algorithm 256-bit (SHA-256),
and unpadded base64url records are mutated from the canonical positive fixture.
Each case establishes only rejection by the named local public decoder.
"""

from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import json
from pathlib import Path
from typing import Any

if __package__:
    from scripts.build_artifact_network_fixture import build_fixture
else:  # Direct ``python scripts/...`` execution.
    from build_artifact_network_fixture import build_fixture
from verifier.interoperability.network import canonical_bytes, digest_bytes


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "examples" / "artifact-network" / "canonical-wire-negative-corpus.json"
SCHEMA = "VSTD-ARTIFACT-NETWORK-WIRE-NEGATIVE-CORPUS-0.1"
MAX_CASES = 32
MAX_CORPUS_BYTES = 2 * 1024 * 1024
CASE_FIELDS = {"case_id", "target", "record", "expected_result", "claim_boundary"}
TARGETS = {"AUTHORITY_MODEL", "COMMIT", "OBJECT", "PUBLISHER", "SIGNED_HEAD", "SILO_TRANSFER"}


def _case(case_id: str, target: str, record: dict[str, Any], defect: str) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "target": target,
        "record": record,
        "expected_result": "REJECT",
        "claim_boundary": (
            f"This case checks rejection of {defect} by the local public {target.lower()} "
            "decoder or materializer only; it does not establish cross-runtime parity or artifact truth."
        ),
    }


def _authority_model(records: dict[str, Any]) -> dict[str, Any]:
    commit = records["commit"]
    transfer = records["silo_transfer"]
    path = commit["authority_model_path"]
    digest = next(item["object"]["object_digest"] for item in commit["census"] if item["path"] == path)
    encoded = next(item["bytes_base64url"] for item in transfer["objects"] if item["digest"] == digest)
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("canonical fixture authority model must be an object")
    return value


def build_negative_corpus() -> dict[str, Any]:
    positive = build_fixture()
    records = positive["records"]
    if not isinstance(records, dict):
        raise ValueError("canonical fixture records must be an object")
    cases: list[dict[str, Any]] = []

    record = deepcopy(records["object"])
    record["unexpected"] = True
    cases.append(_case("object-unknown-field", "OBJECT", record, "an unknown object field"))
    record = deepcopy(records["object"])
    record["object_digest"] = "sha256:not-hex"
    cases.append(_case("object-malformed-digest", "OBJECT", record, "a malformed SHA-256 digest"))

    record = deepcopy(records["publisher"])
    record["genesis_public_key_base64url"] += "="
    cases.append(_case("publisher-malformed-base64url", "PUBLISHER", record, "padded noncanonical base64url"))
    record = deepcopy(records["publisher"])
    record["unexpected"] = "authority"
    cases.append(_case("publisher-unknown-field", "PUBLISHER", record, "an unknown publisher field"))

    record = deepcopy(records["commit"])
    record["census"] = list(reversed(record["census"]))
    cases.append(_case("commit-reordered-census", "COMMIT", record, "a reordered set-like census"))
    record = deepcopy(records["commit"])
    record["authority_axiom_agency"] = list(reversed(record["authority_axiom_agency"]))
    cases.append(_case("commit-reordered-ground-actions", "COMMIT", record, "reordered ground actions"))
    record = deepcopy(records["commit"])
    record["relations"] = [{"relation_type": "EVIDENCES", "source_path": "ground.txt", "target_path": "outside.txt", "mechanism_path": None, "semantic_coordinate": None}]
    cases.append(_case("commit-relation-outside-census", "COMMIT", record, "a relation target outside the census"))
    record = deepcopy(records["commit"])
    record["derivations"][0]["premise_paths"] = ["ground.txt", "outside.txt"]
    cases.append(_case("commit-path-outside-census", "COMMIT", record, "a derivation path outside the census"))
    record = deepcopy(records["commit"])
    record["unexpected"] = False
    cases.append(_case("commit-unknown-field", "COMMIT", record, "an unknown commit field"))

    record = deepcopy(records["signed_head"])
    record["commit_digest"] = "sha256:XYZ"
    cases.append(_case("signed-head-malformed-digest", "SIGNED_HEAD", record, "a malformed selected-commit digest"))
    record = deepcopy(records["signed_head"])
    record["signature_base64url"] = base64.urlsafe_b64encode(bytes(64)).decode("ascii").rstrip("=")
    cases.append(_case("signed-head-signature-substitution", "SIGNED_HEAD", record, "a substituted Ed25519 signature"))

    authority = _authority_model(records)
    record = deepcopy(authority)
    record["states"] = list(reversed(record["states"]))
    cases.append(_case("authority-model-reordered-states", "AUTHORITY_MODEL", record, "reordered authority states"))
    record = deepcopy(authority)
    record["states"][0]["local_authority_additions"] = [{"actor_scope": "ANY_ACTOR", "action": record["states"][0]["ground_actions"][0], "propagation": "LOCAL_ONLY"}]
    cases.append(_case("authority-model-local-redefines-ground", "AUTHORITY_MODEL", record, "a local authority addition redefining a ground action"))
    record = deepcopy(authority)
    record["unexpected"] = []
    cases.append(_case("authority-model-unknown-field", "AUTHORITY_MODEL", record, "an unknown authority-model field"))

    record = deepcopy(records["silo_transfer"])
    record["objects"].pop()
    cases.append(_case("silo-transfer-missing-object", "SILO_TRANSFER", record, "a missing selected object"))
    record = deepcopy(records["silo_transfer"])
    record["objects"].append(deepcopy(record["objects"][0]))
    cases.append(_case("silo-transfer-duplicate-object", "SILO_TRANSFER", record, "a duplicate object digest"))
    record = deepcopy(records["silo_transfer"])
    record["objects"][0]["bytes_base64url"] += "="
    cases.append(_case("silo-transfer-malformed-base64url", "SILO_TRANSFER", record, "padded object base64url"))
    record = deepcopy(records["silo_transfer"])
    record["assessment_receipt"]["assessment"]["claim_boundary"] = "substituted receipt"
    record["portable_manifest"]["assessment_receipt_digest"] = digest_bytes(canonical_bytes(record["assessment_receipt"]))
    cases.append(_case("silo-transfer-receipt-substitution", "SILO_TRANSFER", record, "a manifest-rebound substituted assessment receipt"))
    record = deepcopy(records["silo_transfer"])
    record["signed_head"]["signature_base64url"] = base64.urlsafe_b64encode(bytes(64)).decode("ascii").rstrip("=")
    record["portable_manifest"]["head_digest"] = digest_bytes(canonical_bytes(record["signed_head"]))
    cases.append(_case("silo-transfer-signature-substitution", "SILO_TRANSFER", record, "a manifest-rebound substituted signature"))
    record = deepcopy(records["silo_transfer"])
    record["unexpected"] = None
    cases.append(_case("silo-transfer-unknown-field", "SILO_TRANSFER", record, "an unknown transfer field"))

    cases.sort(key=lambda item: item["case_id"])
    if not 0 < len(cases) <= MAX_CASES or len({item["case_id"] for item in cases}) != len(cases):
        raise ValueError("negative corpus cases must be bounded and uniquely identified")
    if any(set(item) != CASE_FIELDS or item["target"] not in TARGETS or item["expected_result"] != "REJECT" for item in cases):
        raise ValueError("negative corpus case shape is invalid")
    return {
        "schema_version": SCHEMA,
        "cases": cases,
        "claim_boundary": "This corpus specifies deterministic malformed-wire rejection cases derived from the canonical local fixture; it does not establish completeness of adversarial coverage, cross-runtime parity, deployment behavior, artifact correctness, or publisher identity.",
    }


def _read_bounded(path: Path) -> bytes:
    with path.open("rb") as stream:
        value = stream.read(MAX_CORPUS_BYTES + 1)
    if len(value) > MAX_CORPUS_BYTES:
        raise SystemExit("artifact-network negative corpus exceeds its byte bound")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    corpus = build_negative_corpus()
    rendered = (json.dumps(corpus, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    if len(rendered) > MAX_CORPUS_BYTES:
        raise SystemExit("artifact-network negative corpus exceeds its byte bound")
    if args.write:
        TARGET.parent.mkdir(parents=True, exist_ok=True)
        TARGET.write_bytes(rendered)
        print(f"[ARTIFACT NETWORK NEGATIVE CORPUS WRITTEN] cases={len(corpus['cases'])} bytes={len(rendered)}")
        return 0
    if not TARGET.is_file() or _read_bounded(TARGET) != rendered:
        raise SystemExit("artifact-network negative corpus is stale; run with --write")
    print(f"[ARTIFACT NETWORK NEGATIVE CORPUS OK] cases={len(corpus['cases'])} bytes={len(rendered)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
