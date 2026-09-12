"""Strict finite composition command tests for Verifier Standard (VSTD).

JavaScript Object Notation (JSON) fixtures are declared finite models, not
runtime agency proofs. The command-line interface (CLI) keeps legacy assessment
separate from the exact selected finite-product qualification.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from verifier.interoperability.authority_composition import authority_composition_profile_digest, assess_authority_composition
from verifier.interoperability.network import assess_composition, canonical_bytes, digest_bytes
from verifier.runtime.public_cli import main
from test_authority_composition import _fixture


def _command(tmp_path: Path, *, omit: str | None = None) -> tuple[list[str], dict[str, Any], tuple]:
    declaration, _evidence, pairs = _fixture(tmp_path, omit=omit)
    declaration["profile_digest"] = authority_composition_profile_digest()
    paths = []
    for index, (commit, _store) in enumerate(pairs):
        path = tmp_path / f"commit-{index}.json"
        path.write_bytes(canonical_bytes(commit.to_dict()))
        paths.append(path)
    declaration_path = tmp_path / "finite-composition.json"
    declaration_path.write_bytes(canonical_bytes(declaration))
    arguments = ["network", "compose"]
    for (_commit, store), path in zip(pairs[:-1], paths[:-1]):
        arguments.extend(("--silo", str(store.root), str(path)))
    arguments.extend(("--composite-store", str(pairs[-1][1].root),
                      "--composite-commit", str(paths[-1]),
                      "--require-finite-authority-composition", str(declaration_path)))
    return arguments, declaration, pairs


def test_strict_compose_refuses_omitted_transition_despite_legacy_preservation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    arguments, _declaration, _pairs = _command(tmp_path, omit="t01")
    assert main(arguments) != 0
    result = json.loads(capsys.readouterr().out)
    assert result["qualification"] == "NOT_QUALIFIED"
    assert result["selection_binding"] == "BOUND"
    assert result["legacy_assessment"]["authority_axiom_agency"] == "PRESERVED"
    assert result["finite_assessment"]["transition_correspondence"] == "MISMATCH"
    assert result["finite_assessment"]["agency_preservation"] == "UNKNOWN"


def _invoke(arguments: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, Any]]:
    code = main(arguments)
    captured = capsys.readouterr()
    assert not captured.err
    return code, json.loads(captured.out)


def test_exact_product_qualifies_without_rewriting_either_assessment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    arguments, declaration, pairs = _command(tmp_path)
    code, result = _invoke(arguments, capsys)
    assert code == 0
    assert result["qualification"] == "FINITE_COMPOSITION_QUALIFIED"
    assert result["qualification_scope"] == "EXACT_SELECTED_FINITE_ASYNCHRONOUS_INTERLEAVING"
    assert result["selection_binding"] == "BOUND"
    assert result["declaration_digest"] == digest_bytes(canonical_bytes(declaration))
    assert result["coordinates"] == {
        "members": sorted(commit.canonical_digest() for commit, _store in pairs[:-1]),
        "composite": pairs[-1][0].canonical_digest(),
    }
    assert result["legacy_assessment"] == assess_composition(
        tuple(pair[0] for pair in pairs[:-1]), tuple(pair[1] for pair in pairs[:-1]), *pairs[-1],
    )
    evidence = {}
    for commit, store in pairs:
        evidence[commit.canonical_digest()] = canonical_bytes(commit.to_dict())
        model = next(entry.object_record for entry in commit.census if entry.path == commit.authority_model_path)
        evidence[model.object_digest] = store.read_object(model)
    assert result["finite_assessment"] == assess_authority_composition(canonical_bytes(declaration), evidence)
    assert "FULL_SILO_ASSESSMENT_NOT_PERFORMED" in result["finite_assessment"]["residual_obligations"]
    assert "GENERAL_COMPOSED_AGENCY_NOT_ESTABLISHED" in result["finite_assessment"]["residual_obligations"]
    assert not result["reason_codes"]


def test_legacy_failure_blocks_otherwise_passing_finite_product(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    arguments, _declaration, pairs = _command(tmp_path)
    commit, store = pairs[-1]
    record = next(entry.object_record for entry in commit.census if entry.path == "adapter.bin")
    store._object_path(record.object_digest).unlink()
    code, result = _invoke(arguments, capsys)
    assert code != 0
    assert result["qualification"] == "NOT_QUALIFIED"
    assert result["legacy_assessment"]["result"] == "NOT_ADMISSIBLE"
    assert result["finite_assessment"]["transition_correspondence"] == "MATCHED"
    assert result["finite_assessment"]["agency_preservation"] == "PRESERVED"


def test_member_argument_order_does_not_retarget_canonical_member_indices(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    arguments, _declaration, _pairs = _command(tmp_path)
    code, original = _invoke(arguments, capsys)
    assert code == 0
    reordered = arguments[:2] + arguments[5:8] + arguments[2:5] + arguments[8:]
    code, result = _invoke(reordered, capsys)
    assert code == 0
    assert result["coordinates"] == original["coordinates"]
    assert result["finite_assessment"] == original["finite_assessment"]
    assert result["legacy_assessment"]["silos"] == original["legacy_assessment"]["silos"][::-1]


@pytest.mark.parametrize("change", ["duplicate", "wrong_member", "wrong_composite", "missing_member"])
def test_selected_composition_substitution_cannot_qualify(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], change: str,
) -> None:
    arguments, _declaration, _pairs = _command(tmp_path)
    if change == "duplicate":
        arguments[5:8] = arguments[2:5]
    elif change == "missing_member":
        del arguments[5:8]
    else:
        index = 0 if change == "wrong_member" else 2
        path = tmp_path / f"commit-{index}.json"
        value = json.loads(path.read_bytes())
        value["created_at"] = "2026-09-08T00:00:09Z"
        path.write_bytes(canonical_bytes(value))
    code, result = _invoke(arguments, capsys)
    assert code != 0
    assert result["qualification"] == "NOT_QUALIFIED"
    assert result["selection_binding"] == "INVALID"
    expected_reason = "SELECTED_MEMBER_COUNT_INVALID" if change == "missing_member" else "COMPOSITION_SELECTION_MISMATCH"
    assert expected_reason in result["reason_codes"]


@pytest.mark.parametrize("change", ["substituted", "missing", "oversized"])
def test_selected_model_failure_is_not_promoted_or_normalized(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], change: str,
) -> None:
    from verifier.interoperability.authority_composition import MAX_RECORD_BYTES
    arguments, _declaration, pairs = _command(tmp_path)
    commit, store = pairs[-1]
    record = next(entry.object_record for entry in commit.census if entry.path == commit.authority_model_path)
    path = store._object_path(record.object_digest)
    if change == "substituted":
        path.write_bytes(path.read_bytes().replace(b"SETTLE", b"FORGED"))
    elif change == "missing":
        path.unlink()
    else:
        path.write_bytes(b" " * (MAX_RECORD_BYTES + 1))
    code, result = _invoke(arguments, capsys)
    assert code != 0
    assert result["qualification"] == "NOT_QUALIFIED"
    assert result["finite_assessment"]["coordinate_binding"] == ("INVALID" if change == "substituted" else "UNKNOWN")


@pytest.mark.parametrize("change", ["wrong_model_path", "wrong_model_digest", "swapped_state", "swapped_edge"])
def test_declaration_model_and_product_bindings_are_rechecked(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], change: str,
) -> None:
    arguments, declaration, _pairs = _command(tmp_path)
    if change == "wrong_model_path":
        declaration["composite"]["authority_model_path"] = "ground.txt"
    elif change == "wrong_model_digest":
        declaration["composite"]["authority_model_digest"] = "sha256:" + "f" * 64
    elif change == "swapped_state":
        first, second = declaration["state_bindings"][1:3]
        first["member_state_ids"], second["member_state_ids"] = second["member_state_ids"], first["member_state_ids"]
    else:
        declaration["transition_bindings"][0]["member_index"] = 1
    Path(arguments[-1]).write_bytes(canonical_bytes(declaration))
    code, result = _invoke(arguments, capsys)
    assert code != 0
    assert result["qualification"] == "NOT_QUALIFIED"
    assert result["selection_binding"] == "BOUND"
    assert result["finite_assessment"]["coordinate_binding"] == ("INVALID" if change.startswith("wrong_model") else "BOUND")
    if not change.startswith("wrong_model"):
        assert result["finite_assessment"]["transition_correspondence"] == "MISMATCH"


@pytest.mark.parametrize("change", ["profile", "expansion_limit"])
def test_unsupported_or_bounded_check_retains_unknown(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    import verifier.interoperability.authority_composition as finite
    arguments, declaration, _pairs = _command(tmp_path)
    if change == "profile":
        declaration["profile_digest"] = "sha256:" + "0" * 64
        Path(arguments[-1]).write_bytes(canonical_bytes(declaration))
    else:
        monkeypatch.setattr(finite, "MAX_PRODUCT_STATES", 3)
    code, result = _invoke(arguments, capsys)
    assert code != 0
    assert result["qualification"] == "NOT_QUALIFIED"
    assert result["finite_assessment"]["transition_correspondence"] == "UNKNOWN"
    assert "GENERAL_COMPOSED_AGENCY_NOT_ESTABLISHED" in result["finite_assessment"]["residual_obligations"]


@pytest.mark.parametrize("kind", ["declaration", "commit"])
def test_original_noncanonical_bytes_are_not_normalized_into_evidence(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: str,
) -> None:
    arguments, _declaration, _pairs = _command(tmp_path)
    path = Path(arguments[-1]) if kind == "declaration" else tmp_path / "commit-0.json"
    raw = path.read_bytes() + b"\n"
    path.write_bytes(raw)
    code, result = _invoke(arguments, capsys)
    assert code != 0
    assert result["selection_binding"] == "INVALID"
    assert result["qualification"] == "NOT_QUALIFIED"
    if kind == "commit":
        assert result["legacy_assessment"] is None
        assert digest_bytes(raw) in result["coordinates"]["members"]


@pytest.mark.parametrize("kind", ["declaration", "commit"])
@pytest.mark.parametrize("failure", ["missing", "oversized"])
def test_missing_or_oversized_record_never_qualifies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: str, failure: str,
) -> None:
    from verifier.interoperability.authority_composition import MAX_RECORD_BYTES
    arguments, _declaration, _pairs = _command(tmp_path)
    path = Path(arguments[-1]) if kind == "declaration" else tmp_path / "commit-0.json"
    if failure == "missing":
        path.unlink()
    else:
        path.write_bytes(b" " * (MAX_RECORD_BYTES + 1))
    code, result = _invoke(arguments, capsys)
    assert code != 0
    assert result["qualification"] == "NOT_QUALIFIED"
    assert result["selection_binding"] == "UNKNOWN"


@pytest.mark.parametrize("removed", [("--composite-store",), ("--composite-commit",), ("--composite-store", "--composite-commit")])
def test_strict_mode_requires_both_composite_inputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], removed: tuple[str, ...],
) -> None:
    arguments, _declaration, _pairs = _command(tmp_path)
    for flag in removed:
        index = arguments.index(flag)
        del arguments[index:index + 2]
    assert main(arguments) != 0
    captured = capsys.readouterr()
    assert not captured.out
    assert "requires" in captured.err and "--composite" in captured.err


def test_no_flag_retains_exact_legacy_output_and_diagnostic_exit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    arguments, _declaration, pairs = _command(tmp_path, omit="t01")
    code, result = _invoke(arguments[:-2], capsys)
    assert code == 0
    assert result == assess_composition(
        tuple(pair[0] for pair in pairs[:-1]), tuple(pair[1] for pair in pairs[:-1]), *pairs[-1],
    )
    assert "qualification" not in result
    code, result = _invoke(arguments[:5], capsys)
    assert code == 0
    assert result["result"] == "NOT_ADMISSIBLE"
    assert result["composition_completeness"] == "UNKNOWN"


def test_empty_strict_argument_cannot_fall_back_to_legacy_success(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    arguments, _declaration, _pairs = _command(tmp_path)
    arguments[-1] = ""
    code, result = _invoke(arguments, capsys)
    assert code != 0
    assert result["qualification"] == "NOT_QUALIFIED"
    assert result["selection_binding"] == "UNKNOWN"


def test_conflicting_store_copy_cannot_be_erased_by_a_later_valid_copy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    arguments, _declaration, pairs = _command(tmp_path)
    first_commit, first_store = pairs[0]
    record = next(entry.object_record for entry in first_commit.census if entry.path == first_commit.authority_model_path)
    path = first_store._object_path(record.object_digest)
    path.write_bytes(path.read_bytes().replace(b"SETTLE", b"FORGED"))
    for selected in (arguments, arguments[:2] + arguments[5:8] + arguments[2:5] + arguments[8:]):
        code, result = _invoke(selected, capsys)
        assert code != 0
        assert result["selection_binding"] == "INVALID"
        assert result["finite_assessment"]["coordinate_binding"] == "INVALID"
        assert "CONFLICTING_SELECTED_BYTES" in result["reason_codes"]


def test_selected_member_bound_stops_before_commit_reads(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    import verifier.interoperability.composition_qualification as qualification
    arguments, _declaration, _pairs = _command(tmp_path)
    arguments[2:2] = arguments[2:5] * 3
    original = qualification._read_bounded_regular

    def bounded(path: str | Path, maximum: int, label: str) -> bytes:
        assert label == "finite composition declaration"
        return original(path, maximum, label)

    monkeypatch.setattr(qualification, "_read_bounded_regular", bounded)
    code, result = _invoke(arguments, capsys)
    assert code != 0
    assert result["selection_binding"] == "UNKNOWN"
    assert result["reason_codes"] == ["SELECTED_MEMBER_LIMIT"]


@pytest.mark.parametrize("member_count", [0, 1])
def test_too_few_selected_members_are_invalid_despite_missing_commit_bytes(
    tmp_path: Path, member_count: int, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import verifier.interoperability.composition_qualification as qualification
    arguments, _declaration, pairs = _command(tmp_path)
    members = [(pairs[index][1].root, tmp_path / f"missing-{index}.json") for index in range(member_count)]
    original = qualification._read_bounded_regular

    def bounded(path: str | Path, maximum: int, label: str) -> bytes:
        assert label == "finite composition declaration"
        return original(path, maximum, label)

    monkeypatch.setattr(qualification, "_read_bounded_regular", bounded)
    result = qualification.qualify_silo_composition(
        arguments[-1], members, pairs[-1][1].root, tmp_path / "commit-2.json",
    )
    assert result["qualification"] == "NOT_QUALIFIED"
    assert result["selection_binding"] == "INVALID"
    assert result["reason_codes"] == ["SELECTED_MEMBER_COUNT_INVALID"]
    assert result["finite_assessment"]["coordinate_binding"] == "UNKNOWN"
    assert "FULL_SILO_ASSESSMENT_NOT_PERFORMED" in result["finite_assessment"]["residual_obligations"]


@pytest.mark.parametrize("declared_count,selected_count", [(2, 3), (3, 2)])
def test_declared_member_count_mismatch_is_known_before_unavailable_reads(
    tmp_path: Path, declared_count: int, selected_count: int, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import verifier.interoperability.composition_qualification as qualification
    arguments, declaration, pairs = _command(tmp_path)
    if declared_count == 3:
        declaration["members"].append({**declaration["members"][0], "commit_digest": "sha256:" + "f" * 64})
        for binding in declaration["state_bindings"]:
            binding["member_state_ids"].append("initial")
        Path(arguments[-1]).write_bytes(canonical_bytes(declaration))
    original = qualification._read_bounded_regular

    def bounded(path: str | Path, maximum: int, label: str) -> bytes:
        assert label == "finite composition declaration"
        return original(path, maximum, label)

    monkeypatch.setattr(qualification, "_read_bounded_regular", bounded)
    result = qualification.qualify_silo_composition(
        arguments[-1], [(pairs[0][1].root, tmp_path / f"missing-{index}.json") for index in range(selected_count)],
        pairs[-1][1].root, tmp_path / "commit-2.json",
    )
    assert result["selection_binding"] == "INVALID"
    assert result["qualification"] == "NOT_QUALIFIED"
    assert result["reason_codes"] == ["SELECTED_MEMBER_COUNT_INVALID"]
    assert result["finite_assessment"]["coordinate_binding"] == "UNKNOWN"


def test_original_commit_capture_is_once_and_later_file_change_does_not_retarget_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch,
) -> None:
    import verifier.interoperability.composition_qualification as qualification
    arguments, _declaration, pairs = _command(tmp_path)
    original = qualification._read_bounded_regular
    reads: dict[Path, int] = {}
    commit_paths = {tmp_path / f"commit-{index}.json" for index in range(len(pairs))}

    def capture(path: str | Path, maximum: int, label: str) -> bytes:
        raw = original(path, maximum, label)
        resolved = Path(path)
        reads[resolved] = reads.get(resolved, 0) + 1
        if resolved in commit_paths:
            resolved.write_bytes(b"{}")
        return raw

    monkeypatch.setattr(qualification, "_read_bounded_regular", capture)
    code, result = _invoke(arguments, capsys)
    assert code == 0
    assert all(reads[path] == 1 for path in commit_paths)
    assert result["coordinates"]["composite"] == pairs[-1][0].canonical_digest()
    assert "atomic filesystem snapshot" in result["claim_boundary"]
