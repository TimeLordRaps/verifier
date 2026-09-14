"""Native reference corpus for Verifier Standard (VSTD) cross-language replay.

JavaScript Object Notation (JSON) and Secure Hash Algorithm 256-bit (SHA-256)
digests retain exact inputs/results, not a language-independent correctness proof.
"""

from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
from importlib import import_module
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.interoperability.formation_checker import check_formation
from verifier.interoperability.formation_storage import inspect_silo_formation
from verifier.interoperability.network import NetworkError, ObjectRecord, SiloCommit, assess_silo


TARGET = Path(__file__).resolve().parent / "fixtures/formation-interoperability-corpus.json"
RESIDUALS = [
    "SOURCE_INTERPRETATION_NOT_ESTABLISHED", "GROUND_DERIVATION_NOT_ESTABLISHED",
    "SOURCE_TRACE_RELATION_NOT_ESTABLISHED", "SOURCE_LAYER_BOUNDARY_NOT_ESTABLISHED",
    "SELF_STATUS_NOT_ESTABLISHED", "GLOBAL_CYCLE_NOT_ESTABLISHED",
    "COMPLETENESS_NOT_ESTABLISHED", "AGENCY_NOT_CHECKED",
]
PURE_EXPECTED = {
    **{name: ("CHECKED", None) for name in (
        "atom", "application", "identity", "application-step", "composition", "identity-composition",
        "quoted-path", "read-path", "nested-quotation", "nested-read", "unrelated-root",
    )},
    **{name: ("INVALID", "FORMATION_RULE_INVALID") for name in (
        "wrong-application-target", "wrong-composition-endpoints", "read-form", "apply-code", "unused-invalid-node",
    )},
    **{name: ("INVALID", "FORMATION_CERTIFICATE_STEP_INVALID") for name in (
        "certificate-premise-order", "certificate-missing-step",
    )},
    **{name: ("INVALID", "FORMATION_CERTIFICATE_BINDING_INVALID") for name in (
        "certificate-wrong-subject", "certificate-wrong-root", "certificate-wrong-profile",
    )},
    **{name: ("UNKNOWN", "FORMATION_PROFILE_UNSUPPORTED") for name in ("unsupported-profile", "swapped-native-roles")},
    **{name: ("INVALID", "FORMATION_RECORD_INVALID") for name in (
        "boolean-reference", "forward-reference", "duplicate-key", "noncanonical-whitespace",
    )},
    **{name: ("UNKNOWN", "FORMATION_LIMIT_EXCEEDED") for name in (
        "syntax-depth-limit", "dependency-depth-limit", "record-byte-limit",
    )},
}
SILO_EXPECTED = {
    "silo-valid": ("BOUND", "COMPLETE", "MATCHED", "CHECKED"),
    "missing-unrelated": ("BOUND", "INCOMPLETE", "MATCHED", "CHECKED"),
    "substituted-unrelated": ("BOUND", "INVALID", "MATCHED", "CHECKED"),
    "wrong-size-unrelated": ("BOUND", "INVALID", "MATCHED", "CHECKED"),
    "missing-certificate-context-mismatch": ("INVALID", "INCOMPLETE", "MATCHED", None),
    "substituted-subject": ("INVALID", "INVALID", "UNKNOWN", None),
    "wrong-size-subject": ("INVALID", "INVALID", "MATCHED", "CHECKED"),
    "wrong-subject-role": ("INVALID", "COMPLETE", "MATCHED", "CHECKED"),
    "ground-context-mismatch": ("INVALID", "COMPLETE", "MATCHED", "CHECKED"),
    "agency-context-mismatch": ("INVALID", "COMPLETE", "INVALID", "CHECKED"),
    "canonical-agency-reduced": ("UNKNOWN", "COMPLETE", "UNKNOWN", "CHECKED"),
    "canonical-agency-extended": ("UNKNOWN", "COMPLETE", "UNKNOWN", "CHECKED"),
    "agency-digest-inconsistent": ("INVALID", "COMPLETE", "INVALID", "CHECKED"),
    "unsupported-profile": ("UNKNOWN", "COMPLETE", "MATCHED", "UNKNOWN"),
    "same-digest-alias": ("BOUND", "COMPLETE", "MATCHED", "CHECKED"),
    "profile-as-opaque-ground": ("BOUND", "COMPLETE", "MATCHED", "CHECKED"),
    "swapped-path-selectors": ("INVALID", "COMPLETE", "UNKNOWN", "UNKNOWN"),
    "malformed-certificate-missing-unrelated": ("INVALID", "INCOMPLETE", "MATCHED", "INVALID"),
    "profile-coordinate-mismatch-missing-ground": ("INVALID", "INCOMPLETE", "MATCHED", "CHECKED"),
    "alias-size-mismatch": ("BOUND", "INVALID", "MATCHED", "CHECKED"),
}


def _decode(value: str) -> bytes:
    assert "=" not in value
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@pytest.fixture(scope="module")
def corpus() -> dict[str, Any]:
    return json.loads(TARGET.read_bytes())


def test_formation_corpus_generator_exists() -> None:
    module = import_module("scripts.build_formation_corpus")
    assert callable(module.build_corpus)


def test_formation_corpus_is_fresh_deterministic_and_bounded(corpus: dict[str, Any]) -> None:
    module = import_module("scripts.build_formation_corpus")
    raw = TARGET.read_bytes()
    assert raw == _canonical(corpus) == _canonical(module.build_corpus())
    assert module.build_corpus() == corpus
    assert len(raw) < 1_000_000
    assert set(corpus) == {"schema_version", "profile", "pure_cases", "silo_cases"}
    assert corpus["schema_version"] == "VSTD-FORMATION-INTEROPERABILITY-CORPUS-0.1"
    assert len(corpus["pure_cases"]) == len(PURE_EXPECTED) == 30
    assert len(corpus["silo_cases"]) == len(SILO_EXPECTED) == 20
    assert {item["case_id"] for item in corpus["pure_cases"]} == set(PURE_EXPECTED)
    assert {item["case_id"] for item in corpus["silo_cases"]} == set(SILO_EXPECTED)
    profile = corpus["profile"]
    assert profile["digest"] == "sha256:271760d604e1ade55cba4974c658b92263bd3ee8ae343677dd91d0e713fb677f"
    assert _digest(_decode(profile["bytes_base64url"])) == profile["digest"]
    assert module.main(["--check", "--output", str(TARGET)]) == 0


def test_formation_corpus_output_destination_and_stale_check(tmp_path: Path) -> None:
    module = import_module("scripts.build_formation_corpus")
    target = tmp_path / "generated.json"
    assert module.main(["--check", "--output", str(target)]) == 1
    assert module.main(["--output", str(target)]) == 0
    assert target.read_bytes() == TARGET.read_bytes()
    target.write_bytes(target.read_bytes() + b"\n")
    assert module.main(["--check", "--output", str(target)]) == 1


@pytest.mark.parametrize("case_id", list(PURE_EXPECTED))
def test_formation_corpus_pure_replay_and_handwritten_outcome(corpus: dict[str, Any], case_id: str) -> None:
    case = next(item for item in corpus["pure_cases"] if item["case_id"] == case_id)
    report = check_formation(_decode(case["subject_bytes_base64url"]), _decode(case["certificate_bytes_base64url"]))
    assert report == case["expected_report"]
    assert _digest(_canonical(report)) == case["expected_report_digest"]
    status, reason = PURE_EXPECTED[case_id]
    assert report["status"] == status
    assert report["reason_codes"] == ([] if reason is None else [reason])
    assert report["residual_obligations"] == RESIDUALS
    assert (report["observation"] is None) == (status != "CHECKED")


@pytest.mark.parametrize("case_id", list(SILO_EXPECTED))
def test_formation_corpus_silo_replay_and_handwritten_facets(corpus: dict[str, Any], case_id: str) -> None:
    case = next(item for item in corpus["silo_cases"] if item["case_id"] == case_id)
    digests = [item["digest"] for item in case["evidence"]]
    assert digests == sorted(set(digests))
    evidence = {item["digest"]: _decode(item["bytes_base64url"]) for item in case["evidence"]}
    report = inspect_silo_formation(_decode(case["commit_bytes_base64url"]), evidence, **case["paths"])
    assert report == case["expected_report"]
    assert _digest(_canonical(report)) == case["expected_report_digest"]
    formation = report["formation_report"]
    assert (report["coordinate_binding"], report["snapshot_retention"], report["agency_declaration"],
            None if formation is None else formation["status"]) == SILO_EXPECTED[case_id]
    assert report["residual_obligations"] == RESIDUALS
    assert not {"reconstructibility", "self_derivability", "derivation_closure", "completeness",
                "silo_grounding", "authority_axiom_agency"} & set(report)


def test_formation_corpus_has_handwritten_denotation_and_provenance_oracles(corpus: dict[str, Any]) -> None:
    cases = {item["case_id"]: item for item in corpus["pure_cases"]}
    observations = {name: item["expected_report"]["observation"] for name, item in cases.items()}
    atom = json.loads(_decode(cases["atom"]["subject_bytes_base64url"]))["nodes"][0]
    source = _digest(_canonical({"kind": "ATOM", "payload_digest": atom["payload_digest"]}))
    first = _digest(_canonical({"kind": "APPLY", "argument_digest": source}))
    second = _digest(_canonical({"kind": "APPLY", "argument_digest": first}))
    steps = [{"source_digest": source, "target_digest": first}, {"source_digest": first, "target_digest": second}]
    assert observations["atom"]["denotation_digest"] == source
    assert observations["application"]["denotation_digest"] == first
    assert observations["composition"]["path_steps"] == steps
    assert observations["composition"]["denotation_digest"] == _digest(_canonical({
        "kind": "PATH", "source_digest": source, "target_digest": second, "path_steps": steps,
    }))
    assert observations["identity"]["path_steps"] == []
    assert observations["identity"]["source_digest"] == observations["identity"]["target_digest"] == source
    assert observations["application-step"]["denotation_digest"] == observations["identity-composition"]["denotation_digest"]
    assert observations["application-step"]["formation_digest"] != observations["identity-composition"]["formation_digest"]
    quoted = cases["quoted-path"]
    subject_digest = _digest(_decode(quoted["subject_bytes_base64url"]))
    assert observations["quoted-path"]["denotation_digest"] == _digest(_canonical({
        "kind": "CODE", "subject_digest": subject_digest, "node": 5, "dependency_nodes": list(range(6)),
    }))
    assert observations["quoted-path"]["formation_digest"] == _digest(_canonical({"subject_digest": subject_digest, "node": 6}))
    assert observations["read-path"]["denotation_digest"] == observations["composition"]["denotation_digest"]
    assert observations["read-path"]["dependency_nodes"] == list(range(8))
    assert observations["read-path"]["quote_origins"] == [6]
    assert observations["nested-quotation"]["type"] == "CODE(CODE(FORM))"
    nested = observations["nested-read"]
    assert nested["type"] == "FORM" and nested["denotation_digest"] == source
    assert nested["quote_rank"] == 2 and nested["required_depth"] == 5
    assert nested["quote_origins"] == [1, 3] and nested["dependency_nodes"] == [0, 1, 3, 4, 5]
    assert observations["unrelated-root"]["dependency_nodes"] == [1]


def test_formation_corpus_valid_snapshot_does_not_upgrade_existing_silo_axes(corpus: dict[str, Any]) -> None:
    case = next(item for item in corpus["silo_cases"] if item["case_id"] == "silo-valid")
    commit_bytes = _decode(case["commit_bytes_base64url"])
    commit = SiloCommit.from_dict(json.loads(commit_bytes))
    evidence = {item["digest"]: _decode(item["bytes_base64url"]) for item in case["evidence"]}
    original = deepcopy((commit.to_dict(), evidence))

    class RetainedStore:
        def read_object(self, record: ObjectRecord) -> bytes:
            payload = evidence.get(record.object_digest)
            if payload is None or len(payload) != record.size_bytes or _digest(payload) != record.object_digest:
                raise NetworkError("corpus object unavailable")
            return payload

    before = assess_silo(commit, RetainedStore()).to_dict()
    report = inspect_silo_formation(commit_bytes, evidence, **case["paths"])
    after = assess_silo(commit, RetainedStore()).to_dict()
    assert report["formation_report"]["status"] == "CHECKED"
    assert before == after
    assert after["completeness"] == after["authority_axiom_agency"] == "UNKNOWN"
    assert (commit.to_dict(), evidence) == original
