"""Portable receipts do not strengthen Verifier Standard (VSTD) formation claims."""

from __future__ import annotations

import importlib
import base64
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.interoperability import formation_receipt as receipt
from verifier.interoperability.formation_wire import RESIDUAL_OBLIGATIONS, profile_digest
from verifier.interoperability.network import canonical_bytes, digest_bytes

ROOT = Path(__file__).resolve().parents[1]
CORPUS = json.loads((ROOT / "tests/fixtures/formation-interoperability-corpus.json").read_bytes())
CASES = {case["case_id"]: case for case in CORPUS["silo_cases"]}
RECEIPT_CORPUS_PATH = ROOT / "tests/fixtures/formation-receipt-corpus.json"
RECEIPT_CORPUS = json.loads(RECEIPT_CORPUS_PATH.read_bytes())


def raw(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def specimen(name: str = "silo-valid") -> tuple[bytes, bytes, dict[str, bytes]]:
    case = CASES[name]
    commit = raw(case["commit_bytes_base64url"])
    selection = canonical_bytes({"schema_version": receipt.SELECTION_SCHEMA,
                                 "commit_digest": digest_bytes(commit), **case["paths"]})
    evidence = {item["digest"]: raw(item["bytes_base64url"]) for item in case["evidence"]}
    return selection, commit, evidence


def built(name: str = "silo-valid") -> tuple[bytes, bytes, dict[str, bytes], bytes]:
    selection, commit, evidence = specimen(name)
    return selection, commit, evidence, receipt.build_formation_receipt(selection, commit, evidence)


def error(code: str) -> Any:
    return pytest.raises(receipt.FormationReceiptError, match="^" + code + "$")


def test_portable_formation_receipt_interface_exists() -> None:
    module = importlib.import_module("verifier.interoperability.formation_receipt")
    assert callable(module.build_formation_receipt)
    assert callable(module.recheck_formation_receipt)


@pytest.mark.parametrize("name", sorted(CASES))
def test_existing_native_silo_corpus_reproduces_exactly(name: str) -> None:
    selection, commit, evidence, data = built(name)
    value = receipt.decode_formation_receipt(data)
    assert value["inspection"] == CASES[name]["expected_report"]
    assert receipt.recheck_formation_receipt(selection, commit, data, evidence) == value["inspection"]
    assert value["selection_digest"] == digest_bytes(selection)
    assert value["rule_profile_digest"] == profile_digest()
    assert value["inspection"]["residual_obligations"] == list(RESIDUAL_OBLIGATIONS)
    assert not {"status", "completeness", "authority_axiom_agency", "trust"} & value.keys()


def test_inventory_hashes_actual_substitutions_not_the_requested_identity() -> None:
    selection, commit, evidence, data = built("substituted-unrelated")
    value = receipt.decode_formation_receipt(data)
    wrong = [item for item in value["observed_evidence"] if item["requested_digest"] != item["observed_digest"]]
    assert len(wrong) == 1
    item = wrong[0]
    assert item["observed_digest"] == digest_bytes(evidence[item["requested_digest"]])
    assert item["size_bytes"] == len(evidence[item["requested_digest"]])
    assert value["inspection"]["snapshot_retention"] == "INVALID"
    assert value["inspection"]["formation_report"]["status"] == "CHECKED"
    assert receipt.recheck_formation_receipt(selection, commit, data, evidence)["snapshot_retention"] == "INVALID"


def test_other_wrong_bytes_cannot_replay_even_if_status_and_size_are_equal() -> None:
    selection, commit, evidence, data = built("substituted-unrelated")
    value = receipt.decode_formation_receipt(data)
    item = next(item for item in value["observed_evidence"] if item["requested_digest"] != item["observed_digest"])
    evidence[item["requested_digest"]] = b"z" * item["size_bytes"]
    changed = receipt.build_formation_receipt(selection, commit, evidence)
    assert receipt.decode_formation_receipt(changed)["inspection"] == value["inspection"]
    with error("FORMATION_RECEIPT_NOT_REPRODUCED"):
        receipt.recheck_formation_receipt(selection, commit, data, evidence)


def test_missing_objects_are_absent_and_adding_them_changes_the_record() -> None:
    selection, commit, evidence, data = built("missing-unrelated")
    full_selection, full_commit, full_evidence = specimen()
    assert (selection, commit) == (full_selection, full_commit)
    value = receipt.decode_formation_receipt(data)
    assert len(value["observed_evidence"]) == len(evidence)
    assert value["inspection"]["snapshot_retention"] == "INCOMPLETE"
    with error("FORMATION_RECEIPT_NOT_REPRODUCED"):
        receipt.recheck_formation_receipt(selection, commit, data, full_evidence)


def test_aliases_have_one_observation_but_keep_each_census_size_check() -> None:
    _, _, _, data = built("alias-size-mismatch")
    value = receipt.decode_formation_receipt(data)
    requests = [item["requested_digest"] for item in value["observed_evidence"]]
    assert requests == sorted(set(requests))
    assert value["inspection"]["snapshot_retention"] == "INVALID"
    assert "OBJECT_SIZE_MISMATCH" in value["inspection"]["reason_codes"]


def test_mapping_order_and_admitted_extras_do_not_change_receipt() -> None:
    selection, commit, evidence, data = built()
    reversed_evidence = dict(reversed(list(evidence.items())))
    reversed_evidence[digest_bytes(b"irrelevant extra")] = b"unrelated bytes may mismatch their key"
    assert receipt.build_formation_receipt(selection, commit, reversed_evidence) == data


@pytest.mark.parametrize("failure", ["key", "value", "entry", "object", "total"])
def test_extras_cannot_hide_bad_types_or_exceeded_input_budgets(failure: str, monkeypatch: pytest.MonkeyPatch) -> None:
    selection, commit, evidence = specimen()
    code = "FORMATION_RECEIPT_LIMIT_EXCEEDED"
    if failure == "key":
        evidence["not a digest"] = b"extra"
        code = "FORMATION_RECEIPT_INPUT_INVALID"
    elif failure == "value":
        evidence[digest_bytes(b"extra")] = bytearray(b"extra")
        code = "FORMATION_RECEIPT_INPUT_INVALID"
    elif failure == "entry":
        monkeypatch.setattr(receipt, "MAX_EVIDENCE_ENTRIES", len(evidence))
        evidence[digest_bytes(b"extra")] = b"extra"
    elif failure == "object":
        evidence[digest_bytes(b"extra")] = b"x" * (receipt.MAX_OBJECT_BYTES + 1)
    else:
        monkeypatch.setattr(receipt, "MAX_EVIDENCE_BYTES", sum(map(len, evidence.values())))
        evidence[digest_bytes(b"extra")] = b"extra"
    with error(code):
        receipt.build_formation_receipt(selection, commit, evidence)


def test_unsupported_input_types_do_not_invoke_caller_hooks() -> None:
    class ForeignMap(dict):
        def __len__(self) -> int:
            raise AssertionError("mapping hook")
        def items(self) -> Any:
            raise AssertionError("mapping hook")

    class ForeignBytes(bytes):
        def __len__(self) -> int:
            raise AssertionError("byte hook")
        def __bytes__(self) -> bytes:
            raise AssertionError("byte hook")

    class ForeignString(str):
        def __hash__(self) -> int:
            return str.__hash__(self)
        def __str__(self) -> str:
            raise AssertionError("string hook")

    selection, commit, evidence = specimen()
    bad_values = [ForeignMap(evidence), {ForeignString(next(iter(evidence))): b"x"},
                  {next(iter(evidence)): ForeignBytes(b"x")}, {next(iter(evidence)): memoryview(b"x")}]
    for invalid in bad_values:
        with error("FORMATION_RECEIPT_INPUT_INVALID"):
            receipt.build_formation_receipt(selection, commit, invalid)
    with error("FORMATION_RECEIPT_INPUT_INVALID"):
        receipt.build_formation_receipt(selection, ForeignBytes(commit), evidence)
    with error("FORMATION_SELECTION_INVALID"):
        receipt.decode_formation_selection(ForeignBytes(selection))


@pytest.mark.parametrize("commit,status", [
    (b"not json", "INVALID"), (b'{"schema_version":"FUTURE-COMMIT"}', "UNKNOWN"),
    (b"[" * 17 + b"0" + b"]" * 17, "UNKNOWN"),
    (b"[" + b",".join([b"[]"] * 8192) + b"]", "UNKNOWN"),
], ids=["malformed", "unsupported", "native-depth-17", "native-containers-8193"])
def test_unadmitted_commit_preserves_native_result_without_inventing_a_census(commit: bytes, status: str) -> None:
    selection, _, evidence = specimen()
    decoded = json.loads(selection)
    decoded["commit_digest"] = digest_bytes(commit)
    selection = canonical_bytes(decoded)
    data = receipt.build_formation_receipt(selection, commit, evidence)
    value = receipt.decode_formation_receipt(data)
    assert value["observed_evidence"] == []
    assert value["inspection"]["coordinate_binding"] == status
    assert value["inspection"]["commit_digest"] is None
    assert value["inspection"]["coordinates"] == {}
    assert receipt.recheck_formation_receipt(selection, commit, data, {}) == value["inspection"]


def test_foreign_subject_profile_is_reproduced_unknown_under_compiled_rule() -> None:
    selection, commit, evidence, data = built("unsupported-profile")
    value = receipt.decode_formation_receipt(data)
    assert value["rule_profile_digest"] == profile_digest()
    assert receipt.recheck_formation_receipt(selection, commit, data, evidence)["formation_report"]["status"] == "UNKNOWN"


@pytest.mark.parametrize("field", ["selection", "selection_digest", "rule_profile_digest"])
def test_receipt_binding_fields_are_not_replayed_under_another_coordinate(field: str) -> None:
    selection, commit, evidence, data = built()
    value = json.loads(data)
    if field == "selection":
        value[field]["subject_path"] = "other.json"
    else:
        value[field] = digest_bytes(b"foreign")
    changed = canonical_bytes(value)
    assert receipt.decode_formation_receipt(changed) == value
    with error("FORMATION_RECEIPT_BINDING_INVALID"):
        receipt.recheck_formation_receipt(selection, commit, changed, evidence)


def test_changed_commit_cannot_retarget_selection() -> None:
    selection, commit, evidence = specimen()
    with error("FORMATION_RECEIPT_BINDING_INVALID"):
        receipt.build_formation_receipt(selection, commit + b" ", evidence)


def test_well_shaped_carried_claim_is_not_semantically_accepted() -> None:
    selection, commit, evidence, data = built("missing-unrelated")
    value = json.loads(data)
    value["inspection"]["snapshot_retention"] = "COMPLETE"
    value["inspection"]["reason_codes"] = []
    changed = canonical_bytes(value)
    assert receipt.decode_formation_receipt(changed)["inspection"]["snapshot_retention"] == "COMPLETE"
    with error("FORMATION_RECEIPT_NOT_REPRODUCED"):
        receipt.recheck_formation_receipt(selection, commit, changed, evidence)


@pytest.mark.parametrize("mutation", [
    "extra_top", "extra_inspection", "extra_report", "extra_observation", "extra_coordinate",
    "bad_status", "missing_residual", "reordered_residual", "invented_reason", "duplicate_reason",
    "unsorted_inventory", "duplicate_inventory", "bool_size", "bad_digest", "bool_root",
    "bool_depth", "duplicate_nodes", "unsorted_origins", "null_checked", "nonpath_steps", "bad_type",
])
def test_strict_complete_receipt_grammar_refuses_carried_verdict_shape_attacks(mutation: str) -> None:
    *_, data = built()
    value = json.loads(data)
    inspection = value["inspection"]
    report = inspection["formation_report"]
    observation = report["observation"]
    if mutation == "extra_top": value["checked"] = True
    elif mutation == "extra_inspection": inspection["authority"] = "PASSED"
    elif mutation == "extra_report": report["claimed"] = True
    elif mutation == "extra_observation": observation["executed"] = True
    elif mutation == "extra_coordinate": inspection["coordinates"]["subject"]["safe"] = True
    elif mutation == "bad_status": report["status"] = "PASS"
    elif mutation == "missing_residual": report["residual_obligations"].pop()
    elif mutation == "reordered_residual": inspection["residual_obligations"].reverse()
    elif mutation == "invented_reason": inspection["reason_codes"] = ["VERIFIED"]
    elif mutation == "duplicate_reason": inspection["reason_codes"] = ["OBJECT_SIZE_MISMATCH"] * 2
    elif mutation == "unsorted_inventory": value["observed_evidence"].reverse()
    elif mutation == "duplicate_inventory": value["observed_evidence"].append(value["observed_evidence"][0])
    elif mutation == "bool_size": value["observed_evidence"][0]["size_bytes"] = True
    elif mutation == "bad_digest": value["observed_evidence"][0]["observed_digest"] += "\n"
    elif mutation == "bool_root": report["root"] = False
    elif mutation == "bool_depth": observation["required_depth"] = True
    elif mutation == "duplicate_nodes": observation["dependency_nodes"] = [0, 0]
    elif mutation == "unsorted_origins": observation["quote_origins"] = [3, 1]
    elif mutation == "null_checked": report["observation"] = None
    elif mutation == "nonpath_steps": observation["path_steps"] = [{"source_digest": profile_digest(), "target_digest": profile_digest()}]
    elif mutation == "bad_type": observation["type"] = "CODE(FORM"
    with error("FORMATION_RECEIPT_INVALID"):
        receipt.decode_formation_receipt(canonical_bytes(value))


@pytest.mark.parametrize("kind", ["selection", "receipt"])
@pytest.mark.parametrize("failure", ["whitespace", "duplicate", "bad_utf8", "wrong_schema", "deep", "oversized"])
def test_byte_and_canonical_admission_precedes_semantic_decoding(kind: str, failure: str) -> None:
    selection, _, _, data = built()
    data = selection if kind == "selection" else data
    decoder = receipt.decode_formation_selection if kind == "selection" else receipt.decode_formation_receipt
    code = "FORMATION_SELECTION_INVALID" if kind == "selection" else "FORMATION_RECEIPT_INVALID"
    if failure == "whitespace": data += b" "
    elif failure == "duplicate": data = b'{"schema_version":"x","schema_version":"y"}'
    elif failure == "bad_utf8": data = b'"\xff"'
    elif failure == "wrong_schema":
        value = json.loads(data); value["schema_version"] = "FUTURE"; data = canonical_bytes(value)
    elif failure == "deep":
        data = b"[" * 17 + b"0" + b"]" * 17
        code = "FORMATION_RECEIPT_LIMIT_EXCEEDED"
    else:
        data = b" " * (receipt.MAX_SELECTION_BYTES + 1 if kind == "selection" else receipt.MAX_RECEIPT_BYTES + 1)
        code = "FORMATION_RECEIPT_LIMIT_EXCEEDED"
    with error(code): decoder(data)


@pytest.mark.parametrize("path", ["../subject.json", "CON.txt", "folder//x", "trailing.", "subject.json\n"])
def test_selection_uses_native_portable_path_grammar(path: str) -> None:
    selection, _, _ = specimen()
    value = json.loads(selection); value["subject_path"] = path
    with error("FORMATION_SELECTION_INVALID"):
        receipt.decode_formation_selection(canonical_bytes(value))


def test_caller_mutation_after_capture_cannot_change_receipt_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    selection, commit, evidence, expected = built()
    original = receipt.inspect_silo_formation
    def mutation(*args: Any, **kwargs: Any) -> dict[str, Any]:
        evidence.clear()
        return original(*args, **kwargs)
    monkeypatch.setattr(receipt, "inspect_silo_formation", mutation)
    assert receipt.build_formation_receipt(selection, commit, evidence) == expected
    assert evidence == {}


def test_admission_errors_expose_exact_codes() -> None:
    with pytest.raises(receipt.FormationReceiptError) as caught:
        receipt.decode_formation_receipt(b"null")
    assert caught.value.code == str(caught.value) == "FORMATION_RECEIPT_INVALID"


def test_specification_has_an_exact_packaged_mirror() -> None:
    assert (ROOT / "standard/FORMATION_RECEIPT.md").read_bytes() == (ROOT / "src/verifier/specifications/FORMATION_RECEIPT.md").read_bytes()


@pytest.mark.parametrize("case", RECEIPT_CORPUS["cases"], ids=lambda case: case["case_id"])
def test_dedicated_receipt_corpus_has_exact_bytes_and_fresh_inspection(case: dict[str, Any]) -> None:
    selection = raw(case["selection_bytes_base64url"])
    commit = raw(case["commit_bytes_base64url"])
    data = raw(case["receipt_bytes_base64url"])
    evidence = {item["digest"]: raw(item["bytes_base64url"]) for item in case["evidence"]}
    assert receipt.build_formation_receipt(selection, commit, evidence) == data
    assert digest_bytes(data) == case["receipt_digest"]
    assert receipt.recheck_formation_receipt(selection, commit, data, evidence) == case["expected_inspection"]


@pytest.mark.parametrize("case", RECEIPT_CORPUS["recheck_cases"], ids=lambda case: case["case_id"])
def test_dedicated_corpus_preserves_binding_and_semantic_reproduction_failures(case: dict[str, Any]) -> None:
    base = next(item for item in RECEIPT_CORPUS["cases"] if item["case_id"] == case["base_case_id"])
    selection = raw(base["selection_bytes_base64url"])
    commit = raw(base["commit_bytes_base64url"])
    evidence = {item["digest"]: raw(item["bytes_base64url"]) for item in base["evidence"]}
    data = raw(case["receipt_bytes_base64url"])
    receipt.decode_formation_receipt(data)
    with error(case["expected_error"]):
        receipt.recheck_formation_receipt(selection, commit, data, evidence)


def test_corpus_handwritten_identity_and_negative_outcomes() -> None:
    values = {item["case_id"]: item["expected_inspection"] for item in RECEIPT_CORPUS["cases"]}
    assert values["commit-malformed"]["coordinate_binding"] == "INVALID"
    for name in ("commit-unsupported", "commit-native-depth-limit", "commit-native-container-limit"):
        assert values[name]["coordinate_binding"] == "UNKNOWN"
        assert values[name]["reason_codes"] == ["COMMIT_UNSUPPORTED_OR_LIMITED"]
    composition = values["formation-composition"]["formation_report"]["observation"]
    identity = values["formation-identity-composition"]["formation_report"]["observation"]
    read_path = values["formation-read-path"]["formation_report"]["observation"]
    assert composition["type"] == identity["type"] == "PATH"
    assert len(composition["path_steps"]) == len(read_path["path_steps"]) == 2
    assert len(identity["path_steps"]) == 1
    assert composition["denotation_digest"] == read_path["denotation_digest"]
    assert composition["formation_digest"] != read_path["formation_digest"]
    assert identity["denotation_digest"] == digest_bytes(canonical_bytes({
        "kind": "PATH", "source_digest": composition["source_digest"],
        "target_digest": composition["path_steps"][0]["target_digest"],
        "path_steps": composition["path_steps"][:1],
    }))
    nested = values["formation-nested-read"]["formation_report"]["observation"]
    assert nested["type"] == "FORM"
    assert nested["quote_rank"] == 2
    assert nested["required_depth"] == 5
    assert nested["quote_origins"] == [1, 3]
    assert nested["dependency_nodes"] == [0, 1, 3, 4, 5]
    assert values["formation-unused-invalid-node"]["formation_report"]["status"] == "INVALID"
    assert values["formation-dependency-depth-limit"]["formation_report"]["status"] == "UNKNOWN"


def test_corpus_generator_is_deterministic_fresh_and_supports_output_destination(tmp_path: Path) -> None:
    import importlib.util
    spec = importlib.util.spec_from_file_location("formation_receipt_corpus_generator", ROOT / "scripts/build_formation_receipt_corpus.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    expected = RECEIPT_CORPUS_PATH.read_bytes()
    assert len(expected) <= module.MAX_CORPUS_BYTES
    assert module.build_corpus() == module.build_corpus() == expected
    target = tmp_path / "receipt-corpus.json"
    assert module.main(["--output", str(target)]) == 0
    assert target.read_bytes() == expected
    assert module.main(["--check", "--output", str(target)]) == 0
    target.write_bytes(b"stale")
    assert module.main(["--check", "--output", str(target)]) == 1


@pytest.mark.parametrize("bound", ["observed_count", "observed_object", "observed_total", "commit_bytes"])
def test_receipt_boundary_limits_have_explicit_refusal_codes(bound: str) -> None:
    selection, commit, evidence, data = built()
    if bound == "commit_bytes":
        with error("FORMATION_RECEIPT_LIMIT_EXCEEDED"):
            receipt.build_formation_receipt(selection, b"x" * (receipt.MAX_COMMIT_BYTES + 1), evidence)
        return
    value = json.loads(data)
    if bound == "observed_count":
        value["observed_evidence"] = value["observed_evidence"][:1] * 257
    elif bound == "observed_object":
        value["observed_evidence"][0]["size_bytes"] = receipt.MAX_OBJECT_BYTES + 1
    else:
        assert len(value["observed_evidence"]) == 5
        for item in value["observed_evidence"]:
            item["size_bytes"] = receipt.MAX_OBJECT_BYTES
    with error("FORMATION_RECEIPT_LIMIT_EXCEEDED"):
        receipt.decode_formation_receipt(canonical_bytes(value))
