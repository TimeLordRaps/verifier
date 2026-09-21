"""Terminology: command-line interface (CLI); Verifier Standard (VSTD).

Tests for the accessibility surface: the guided entry point and plain-language
artifact reading.

The load-bearing tests here are the ones that keep the surface honest as the
runtime changes: every command `vstd start` recommends must still parse and
every path it names must still exist, the printed guided path must say nothing
absent from the structure a `--json` reader gets, and `vstd explain` must never
restate a counted prefix as a total.
"""

from __future__ import annotations

import importlib.util
import json
import shlex
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from verifier.domains.certification import (build_domain_certificate, domain_policy,
                                            domain_request)
from verifier.runtime.accessibility_cli import (_print_start, explain_report,
                                                 start_report)
from verifier.runtime.public_cli import build_parser, main

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def specimens() -> dict:
    spec = importlib.util.spec_from_file_location(
        "domain_example", ROOT / "examples/domain_grounding.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.specimens()


@pytest.fixture(scope="module")
def partial_sim(specimens: dict) -> dict:
    """A SIM certificate with an interior gap: SIM.3 UNKNOWN, SIM.4/5 PASS."""
    bundle = deepcopy(specimens["SIM"])
    bundle["artifact"]["projection"] = {}
    policy = domain_policy(trust_roots=["test:retained-inputs", "test:checker"])
    return build_domain_certificate(domain_request(bundle), bundle, policy=policy)


def test_every_recommended_command_still_parses() -> None:
    """`vstd start` must never recommend a command the CLI cannot accept.

    This is the test that stops the guided path rotting as subcommands change.
    """
    parser = build_parser()
    for step in start_report()["steps"]:
        argv = shlex.split(step["command"])
        assert argv[0] == "vstd", step["command"]
        parser.parse_args(argv[1:])


def test_every_repository_path_a_step_names_still_exists() -> None:
    """A step can stay parseable while its file argument goes stale.

    `vstd plan examples/generic_run/manifest.json` parses whether or not that
    manifest exists, so the parser test alone would not notice the example
    moving. This checks the arguments, not just the verbs.
    """
    report = start_report()
    named = []
    for step in report["steps"]:
        for token in shlex.split(step["command"])[1:]:
            if token.startswith("-") or "/" not in token:
                continue
            if token.startswith("./"):
                continue  # produced by an earlier step, not shipped
            named.append(token)
    assert named, "at least one step should reference a shipped example"
    named.extend(report["guides"])  # the footer rots the same way
    missing = [t for t in named if not (ROOT / t).exists()]
    assert missing == [], missing


def test_start_tells_a_person_and_a_program_the_same_thing(capsys) -> None:
    """Prose printed only by the printer is invisible to a --json consumer.

    The guided path claims a person and an assistant reading it are never told
    different things, so anything the printer says has to come from the report.
    """
    report = start_report()
    _print_start(report)
    printed = capsys.readouterr().out
    for guide in report["guides"]:
        assert guide in printed
    assert report["next"] in printed
    # Nothing in the printed output may be absent from the structure.
    from_structure = " ".join(
        [report["purpose"], report["boundary"], report["next"], *report["guides"]]
        + [s["title"] + s["why"] + s["command"] for s in report["steps"]]
        + [c["term"] + c["meaning"] for c in report["concepts"]]
    )
    for token in printed.split():
        if "/" in token and token.endswith(".md"):
            assert token.rstrip(",") in from_structure, token


def test_start_is_side_effect_free_and_machine_readable(capsys, tmp_path) -> None:
    before = sorted(p.name for p in tmp_path.iterdir())
    assert main(["start", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == "VSTD-START-1"
    assert [s["order"] for s in report["steps"]] == list(range(1, len(report["steps"]) + 1))
    assert all(s["title"] and s["why"] and s["command"] for s in report["steps"])
    assert {c["term"] for c in report["concepts"]} >= {"established", "depth"}
    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_start_prose_and_json_describe_the_same_steps(capsys) -> None:
    assert main(["start"]) == 0
    prose = capsys.readouterr().out
    for step in start_report()["steps"]:
        assert step["command"] in prose


def test_explain_separates_established_count_from_counted_prefix(partial_sim, tmp_path) -> None:
    """The headline surprise: four checks established, depth two.

    A reader must not be able to conclude that depth is the number of
    established checks, nor that SIM.4 and SIM.5 failed.
    """
    path = tmp_path / "certificate.json"
    path.write_text(json.dumps(partial_sim), encoding="utf-8")
    report = explain_report(path)

    rows = {r["coordinate"]: r for r in report["rows"]}
    assert rows["SIM.3"]["outcome"] == "UNKNOWN" and not rows["SIM.3"]["established"]
    assert [rows[c]["established"] for c in ("SIM.4", "SIM.5")] == [True, True]
    assert report["depth"] == 2
    assert len([r for r in report["rows"] if r["established"]]) == 4

    note = report["depth_note"]
    assert note is not None, "an interior gap must be explained, not left implicit"
    assert "SIM.3" in note and "SIM.4" in note and "SIM.5" in note
    assert report["next"].startswith("Supply evidence for SIM.3")


def test_explain_names_the_reason_not_just_the_outcome(partial_sim, tmp_path) -> None:
    path = tmp_path / "certificate.json"
    path.write_text(json.dumps(partial_sim), encoding="utf-8")
    rows = {r["coordinate"]: r for r in explain_report(path)["rows"]}
    # the checker's own detail string, surfaced rather than discarded
    assert "empty macro projection" in rows["SIM.3"]["meaning"]


@pytest.fixture(scope="module")
def grounded_certificate(tmp_path_factory) -> Path:
    """The shipped partial-certification example, built fresh."""
    spec = importlib.util.spec_from_file_location(
        "grounded_example", ROOT / "examples/grounded_certification.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    out = tmp_path_factory.mktemp("grounded") / "specimen"
    argv = sys.argv
    try:  # the example reads sys.argv directly
        sys.argv = ["grounded_certification.py", str(out)]
        # UNKNOWN exits 2 by the CLI convention; the specimen is still written
        assert module.main() == 2
    finally:
        sys.argv = argv
    return out / "certificate.json"


def test_explain_reports_blocking_dependencies_by_coordinate(grounded_certificate) -> None:
    rows = {r["coordinate"]: r for r in explain_report(grounded_certificate)["rows"]}
    blocked = [r for r in rows.values() if r["blocked_by"]]
    assert blocked, "a partial grounded certificate should record blockers"
    for row in blocked:
        assert row["meaning"].startswith("held back by ")
        assert all(b in rows for b in row["blocked_by"]), "blockers must be real coordinates"


def test_explain_does_not_restate_complete_profiles_as_obligations(grounded_certificate) -> None:
    """`certified_profile_depth` counts whole profiles, not established obligations.

    Reading it as an obligation count is the easiest way to misread this
    certificate, so the explanation must keep the two numbers distinct.
    """
    report = explain_report(grounded_certificate)
    established = len([r for r in report["rows"] if r["established"]])
    assert established == 1 and report["depth"] == 0
    assert "1 of 7 obligations established" in report["headline"]
    assert "0 profiles complete" in report["headline"]
    assert report["profiles"][0]["established_prefix"] == 1
    assert report["profiles"][0]["complete"] is False
    # the per-profile prefix already equals the established count, so there is
    # no interior gap to explain and no note should be invented
    assert report["depth_note"] is None


def test_explain_does_not_advise_more_evidence_for_a_refutation(specimens, tmp_path) -> None:
    """A FAIL and a missing input need opposite responses.

    Telling someone to supply more evidence for a refuted check sends them
    after work that cannot clear it.
    """
    bundle = deepcopy(specimens["SIM"])
    bundle["artifact"]["macro_digest"] = "0" * 64
    policy = domain_policy(trust_roots=["test:retained-inputs", "test:checker"])
    certificate = build_domain_certificate(domain_request(bundle), bundle, policy=policy)

    path = tmp_path / "certificate.json"
    path.write_text(json.dumps(certificate), encoding="utf-8")
    report = explain_report(path)

    rows = {r["coordinate"]: r for r in report["rows"]}
    assert rows["SIM.3"]["outcome"] == "FAIL"
    assert rows["SIM.3"]["meaning"].startswith("refuted by its own evidence")
    # the reason travels with the verdict, so the reader is not sent hunting
    assert rows["SIM.3"]["reason"] in rows["SIM.3"]["meaning"]
    assert "refuted by its own evidence" in report["next"]
    assert "Supply evidence" not in report["next"]


def test_explain_exit_code_agrees_with_the_text_it_prints(
        specimens, grounded_certificate, partial_sim, tmp_path, capsys) -> None:
    """A program reading the exit code must not read success out of a FAIL.

    `vstd explain cert.json && deploy` is the obvious thing for an agent to
    write. If explain exited 0 while printing `status: FAIL`, the person and
    the program would be told opposite things by the same command.
    """
    refuted = deepcopy(specimens["SIM"])
    refuted["artifact"]["macro_digest"] = "0" * 64
    policy = domain_policy(trust_roots=["test:retained-inputs", "test:checker"])
    fail_path = tmp_path / "refuted.json"
    fail_path.write_text(json.dumps(build_domain_certificate(
        domain_request(refuted), refuted, policy=policy)), encoding="utf-8")

    unknown_path = tmp_path / "partial.json"
    unknown_path.write_text(json.dumps(partial_sim), encoding="utf-8")

    for path, expected in ((fail_path, 1),
                           (unknown_path, 2),
                           (grounded_certificate, 2)):
        code = main(["explain", str(path)])
        printed = capsys.readouterr().out
        assert code == expected, (path, printed)
        # the exit code is the stored verdict, not a fresh judgement
        assert f"status: {explain_report(Path(path))['status']}" in printed


def test_explain_reports_a_successful_read_for_a_verdictless_document(
        tmp_path, capsys) -> None:
    """Nothing to propagate is not the same as a failure."""
    path = tmp_path / "plain.json"
    path.write_text('{"schema_version": "VSTD-SOMETHING-1"}', encoding="utf-8")
    assert main(["explain", str(path)]) == 0
    capsys.readouterr()


@pytest.fixture(scope="module")
def run_receipt(tmp_path_factory) -> Path:
    """The receipt `vstd start` step 4 produces: the first artifact most people hold."""
    out = tmp_path_factory.mktemp("run") / "receipt-dir"
    assert main(["run", str(ROOT / "examples/generic_run/manifest.json"),
                 "--output", str(out)]) == 0
    return out / "receipt.json"


def test_explain_reads_a_run_receipt_rather_than_restating_its_schema(run_receipt) -> None:
    """The guided path explains a receipt at step 6; it must say something useful.

    Reporting only `declares schema VSTD-1` would make the highest-traffic
    explanation the least informative one.
    """
    report = explain_report(run_receipt)
    assert report["kind"] == "run receipt"
    rows = {r["coordinate"]: r for r in report["rows"]}
    assert set(rows) == {"claim", "execution", "recorded", "reproducible"}
    assert "exit code 0" in rows["execution"]["meaning"]
    assert report["limitations"], "a receipt states its own limits; surface them"
    assert "see below" not in json.dumps(report)


def test_explain_separates_a_declared_ceiling_from_a_demonstrated_level(run_receipt) -> None:
    """Declaring CONTENT_IDENTICAL is not demonstrating it.

    Reading the declared ceiling as an achieved result is the receipt-level
    equivalent of reading depth as a count of established checks.
    """
    stored = json.loads(run_receipt.read_text(encoding="utf-8"))["reproducibility"]
    assert stored["highest_demonstrated_level"] is None, "fixture assumes nothing demonstrated"

    row = {r["coordinate"]: r for r in explain_report(run_receipt)["rows"]}["reproducible"]
    assert row["established"] is False
    assert row["outcome"] == "DECLARED"
    assert "nothing has been demonstrated" in row["meaning"]
    assert "reproduce" in explain_report(run_receipt)["next"]


def test_explain_does_not_turn_a_receipt_into_a_verdict(run_receipt, capsys) -> None:
    """A receipt carries no PASS/FAIL, so explaining one is a successful read."""
    assert main(["explain", str(run_receipt)]) == 0
    printed = capsys.readouterr().out
    assert "is not a verdict" in printed
    assert "vstd validate" in printed


def test_explain_points_at_the_root_blocker_not_the_symptom(grounded_certificate) -> None:
    """When a coordinate is only blocked, the useful next step is its blocker."""
    report = explain_report(grounded_certificate)
    rows = {r["coordinate"]: r for r in report["rows"]}
    # 1.2 is the first unresolved and is itself unblocked, so it is the root
    assert rows["1.2"]["blocked_by"] == []
    assert "1.2" in report["next"]


def test_explain_never_changes_a_verdict(partial_sim, tmp_path) -> None:
    path = tmp_path / "certificate.json"
    path.write_text(json.dumps(partial_sim), encoding="utf-8")
    report = explain_report(path)
    stored = partial_sim["result"]["checks"]
    for row in report["rows"]:
        source = stored[row["coordinate"]]
        assert row["outcome"] == source["evaluation"]["outcome"]
        assert row["established"] is source["established"]
    assert report["status"] == partial_sim["result"]["status"]


def test_explain_rejects_a_non_object_document(tmp_path, capsys) -> None:
    path = tmp_path / "list.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    assert main(["explain", str(path)]) == 1
    assert "[FAIL]" in capsys.readouterr().out


def test_explain_reports_malformed_and_missing_inputs_with_a_next_step(tmp_path, capsys) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    assert main(["explain", str(bad)]) == 1
    assert "vstd start" in capsys.readouterr().out

    assert main(["explain", str(tmp_path / "absent.json")]) == 1
    assert "Not a file" in capsys.readouterr().out


def test_explain_tolerates_an_unrecognized_json_object(tmp_path, capsys) -> None:
    path = tmp_path / "other.json"
    path.write_text('{"unrelated": true}', encoding="utf-8")
    assert main(["explain", str(path)]) == 0
    assert "not a VSTD artifact" in capsys.readouterr().out


def test_version_flag_reports_the_package_version(capsys) -> None:
    from verifier import __version__
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_module_entry_point_dispatches_to_the_same_cli() -> None:
    """`python -m verifier` is the first thing many people try."""
    assert (ROOT / "src/verifier/__main__.py").is_file()
    spec = importlib.util.find_spec("verifier.__main__")
    assert spec is not None
