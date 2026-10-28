"""Refutable tests for source-bound Tier 1 pytest evidence replay.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Extensible Markup Language (XML).  The nested pytest specimens are isolated
from this test module so the evidence primitive never recursively runs itself.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest

from verifier.runtime import self_polish_evidence as evidence


REPOSITORY = "https://example.invalid/verifier.git"
REVISION = "1" * 40
EXPECTED = {
    "tier1.complete": evidence.CASE_KIND_ORDER,
}


def _write(root: Path, relative: str, raw: bytes) -> None:
    target = root.joinpath(*relative.split("/"))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)


def _fixture(tmp_path: Path, *, unknown_body: str = "assert None is None") -> tuple[Path, dict, bytes]:
    root = tmp_path / "selected-repository"
    (root / ".git" / "refs" / "heads").mkdir(parents=True)
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii", newline="\n")
    (root / ".git" / "refs" / "heads" / "main").write_text(
        REVISION + "\n", encoding="ascii", newline="\n",
    )
    (root / ".git" / "config").write_text(
        '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n'
        f"\turl = {REPOSITORY}\n",
        encoding="utf-8", newline="\n",
    )
    mechanism_raw = Path(evidence.__file__).read_bytes()
    source_raw = b"def bounded_value():\n    return 7\n"
    test_raw = (
        "def test_negative_refusal():\n"
        "    try:\n"
        "        raise ValueError('refused')\n"
        "    except ValueError:\n"
        "        pass\n\n"
        "def test_positive_behavior():\n"
        "    assert 3 + 4 == 7\n\n"
        "def test_unknown_preserved():\n"
        f"    {unknown_body}\n"
    ).encode("utf-8")
    selected = {
        evidence.PRIMARY_MECHANISM_PATH: ("MECHANISM", mechanism_raw),
        "src/specimen.py": ("SOURCE", source_raw),
        "tests/test_contract.py": ("TEST", test_raw),
    }
    for relative, (_, raw) in selected.items():
        _write(root, relative, raw)
    files = [
        {"path": path, "role": role, "sha256": evidence.bytes_digest(raw)}
        for path, (role, raw) in sorted(selected.items())
    ]
    obligations = [
        {
            "obligation_id": "tier1.complete",
            "case_kind": "POSITIVE",
            "node_id": "tests/test_contract.py::test_positive_behavior",
            "source_path": "src/specimen.py",
            "test_path": "tests/test_contract.py",
            "mechanism_path": evidence.PRIMARY_MECHANISM_PATH,
        },
        {
            "obligation_id": "tier1.complete",
            "case_kind": "NEGATIVE",
            "node_id": "tests/test_contract.py::test_negative_refusal",
            "source_path": "src/specimen.py",
            "test_path": "tests/test_contract.py",
            "mechanism_path": evidence.PRIMARY_MECHANISM_PATH,
        },
        {
            "obligation_id": "tier1.complete",
            "case_kind": "UNKNOWN",
            "node_id": "tests/test_contract.py::test_unknown_preserved",
            "source_path": "src/specimen.py",
            "test_path": "tests/test_contract.py",
            "mechanism_path": evidence.PRIMARY_MECHANISM_PATH,
        },
    ]
    manifest = {
        "schema_version": evidence.MANIFEST_SCHEMA,
        "source_coordinate": {"repository": REPOSITORY, "revision": REVISION},
        "files": files,
        "obligations": obligations,
    }
    raw = evidence.canonical_bytes(manifest)
    return root, manifest, raw


def _replay(
    root: Path,
    raw: bytes,
    expected: dict[str, tuple[str, ...] | list[str]] | None = None,
) -> dict:
    return evidence.replay_self_polish_evidence(
        raw,
        root,
        expected_manifest_digest=evidence.bytes_digest(raw),
        expected_mechanism_digest=evidence.mechanism_digest(),
        expected_obligations=EXPECTED if expected is None else expected,
    )


def test_exact_selected_nodes_produce_bounded_mechanical_pass(tmp_path: Path) -> None:
    root, _, raw = _fixture(tmp_path)
    receipt = _replay(root, raw)
    assert receipt["status"] == "PASS", receipt
    assert receipt["counts"] == {
        "expected": 3, "collected": 3, "passed": 3, "failed": 0,
        "skipped": 0, "xfailed": 0, "xpassed": 0,
    }
    assert receipt["source_coordinate"] == {
        "repository": REPOSITORY,
        "revision": REVISION,
        "selected_files_digest": receipt["source_coordinate"]["selected_files_digest"],
        "scope": "SELECTED_FILES_ONLY",
    }
    assert receipt["manifest_digest"] == evidence.bytes_digest(raw)
    assert receipt["stable_replay_set_digest"].startswith("sha256:")
    assert receipt["evidence_digest"].startswith("sha256:")
    assert set(receipt["run_artifacts"]) == {
        "pytest_trace_digest", "junit_xml_digest", "stdout_digest", "stderr_digest",
    }
    assert all(value.startswith("sha256:")
               for value in receipt["run_artifacts"].values())
    assert [row["obligation_id"] for row in receipt["memberships"]] == sorted(EXPECTED)
    assert all(row["status"] == "PASS" for row in receipt["memberships"])
    assert all(row["stable_replay_digest"].startswith("sha256:")
               for row in receipt["memberships"])
    assert all(set(row) == {
        "obligation_id", "cases", "status", "stable_replay_digest",
    }
               for row in receipt["memberships"])
    assert [case["case_kind"] for case in receipt["memberships"][0]["cases"]] \
        == list(evidence.CASE_KIND_ORDER)
    assert receipt["polished"] is False
    assert receipt["whole_tier_conformance"] == "NOT_ESTABLISHED"
    assert receipt["release_authority"] == "NONE"
    assert receipt["provider_states"] == "OUT_OF_SCOPE"
    assert not list(root.rglob(".pytest_cache"))
    assert not list(root.rglob("__pycache__"))


def test_each_membership_requires_positive_negative_and_unknown_cases(
    tmp_path: Path,
) -> None:
    root, _, raw = _fixture(tmp_path)
    receipt = _replay(root, raw)
    assert receipt["status"] == "PASS", receipt
    assert len(receipt["memberships"]) == 1
    membership = receipt["memberships"][0]
    assert membership["obligation_id"] == "tier1.complete"
    assert membership["status"] == "PASS"
    assert [case["case_kind"] for case in membership["cases"]] == [
        "POSITIVE", "NEGATIVE", "UNKNOWN",
    ]


def test_equivalent_replays_have_the_same_membership_evidence_coordinate(
    tmp_path: Path,
) -> None:
    root, _, raw = _fixture(tmp_path)
    first = _replay(root, raw)
    second = _replay(root, raw)
    assert first["status"] == second["status"] == "PASS"
    assert first["memberships"][0]["stable_replay_digest"] \
        == second["memberships"][0]["stable_replay_digest"]
    assert first["stable_replay_set_digest"] == second["stable_replay_set_digest"]


def test_volatile_run_artifacts_are_separate_from_stable_replay_coordinates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, raw = _fixture(tmp_path)
    invocation = 0

    def run(argv, **kwargs):
        nonlocal invocation
        invocation += 1
        nodes = argv[argv.index("--") + 1:]
        Path(kwargs["env"]["VSTD_SELF_POLISH_TRACE"]).write_bytes(_trace(nodes))
        junit = _junit(len(nodes)).replace(
            b"<testsuite ", f'<testsuite timestamp="run-{invocation}" '.encode("ascii"), 1,
        )
        Path(argv[argv.index("--junitxml") + 1]).write_bytes(junit)
        kwargs["stdout"].write(f"run-{invocation}".encode("ascii"))
        kwargs["stdout"].flush()
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(evidence.subprocess, "run", run)
    first = _replay(root, raw)
    second = _replay(root, raw)
    assert first["status"] == second["status"] == "PASS"
    assert first["run_artifacts"]["junit_xml_digest"] \
        != second["run_artifacts"]["junit_xml_digest"]
    assert first["run_artifacts"]["stdout_digest"] \
        != second["run_artifacts"]["stdout_digest"]
    assert first["evidence_digest"] != second["evidence_digest"]
    assert first["receipt_digest"] != second["receipt_digest"]
    assert first["memberships"][0]["stable_replay_digest"] \
        == second["memberships"][0]["stable_replay_digest"]
    assert first["stable_replay_set_digest"] == second["stable_replay_set_digest"]


def test_stable_replay_digest_changes_with_bytes_mapping_and_outcomes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, manifest, raw = _fixture(tmp_path / "baseline")
    _fake_completed_run(monkeypatch, root)
    baseline = _replay(root, raw)

    changed_root, changed_manifest, _ = _fixture(tmp_path / "changed-byte")
    changed_source = b"def bounded_value():\n    return 8\n"
    (changed_root / "src" / "specimen.py").write_bytes(changed_source)
    next(row for row in changed_manifest["files"]
         if row["path"] == "src/specimen.py")["sha256"] \
        = evidence.bytes_digest(changed_source)
    changed_raw = evidence.canonical_bytes(changed_manifest)
    _fake_completed_run(monkeypatch, changed_root)
    changed_bytes = _replay(changed_root, changed_raw)

    mapped_root, mapped_manifest, _ = _fixture(tmp_path / "changed-mapping")
    positive = mapped_manifest["obligations"][0]
    negative = mapped_manifest["obligations"][1]
    positive["node_id"], negative["node_id"] = negative["node_id"], positive["node_id"]
    mapped_raw = evidence.canonical_bytes(mapped_manifest)
    _fake_completed_run(monkeypatch, mapped_root)
    changed_mapping = _replay(mapped_root, mapped_raw)

    _fake_completed_run(monkeypatch, root, skipped=True)
    changed_outcomes = _replay(root, raw)

    baseline_digest = baseline["memberships"][0]["stable_replay_digest"]
    assert baseline["status"] == changed_bytes["status"] == changed_mapping["status"] == "PASS"
    assert changed_outcomes["status"] == "FAIL"
    assert changed_outcomes["counts"] != baseline["counts"]
    assert changed_outcomes["memberships"][0]["status"] != baseline["memberships"][0]["status"]
    assert baseline_digest != changed_bytes["memberships"][0]["stable_replay_digest"]
    assert baseline_digest != changed_mapping["memberships"][0]["stable_replay_digest"]
    assert baseline_digest != changed_outcomes["memberships"][0]["stable_replay_digest"]


def test_case_coverage_cannot_be_borrowed_between_memberships(tmp_path: Path) -> None:
    root, manifest, _ = _fixture(tmp_path)
    manifest["obligations"][0]["obligation_id"] = "tier1.first"
    manifest["obligations"][1]["obligation_id"] = "tier1.second"
    manifest["obligations"][2]["obligation_id"] = "tier1.second"
    raw = evidence.canonical_bytes(manifest)
    expected = {
        "tier1.first": evidence.CASE_KIND_ORDER,
        "tier1.second": evidence.CASE_KIND_ORDER,
    }
    receipt = _replay(root, raw, expected)
    assert receipt["status"] == "FAIL"
    assert "REQUIRED_OBLIGATION_CASE_UNMAPPED" in receipt["invalidators"]


def test_bounds_admit_exactly_45_memberships_and_135_unique_cases(
    tmp_path: Path,
) -> None:
    root, manifest, _ = _fixture(tmp_path)
    source_lines = []
    obligations = []
    expected = {}
    for index in range(45):
        identifier = f"tier1.member-{index:02d}"
        expected[identifier] = evidence.CASE_KIND_ORDER
        for case_kind in evidence.CASE_KIND_ORDER:
            name = f"test_member_{index:02d}_{case_kind.casefold()}"
            if case_kind == "NEGATIVE":
                body = (
                    f"def {name}():\n"
                    "    try:\n"
                    "        raise ValueError('refused')\n"
                    "    except ValueError:\n"
                    "        pass\n\n"
                )
            else:
                body = f"def {name}():\n    assert True\n\n"
            source_lines.append(body)
            obligations.append({
                "obligation_id": identifier,
                "case_kind": case_kind,
                "node_id": f"tests/test_contract.py::{name}",
                "source_path": "src/specimen.py",
                "test_path": "tests/test_contract.py",
                "mechanism_path": evidence.PRIMARY_MECHANISM_PATH,
            })
    test_raw = "".join(source_lines).encode("utf-8")
    (root / "tests" / "test_contract.py").write_bytes(test_raw)
    next(row for row in manifest["files"] if row["role"] == "TEST")["sha256"] \
        = evidence.bytes_digest(test_raw)
    manifest["obligations"] = obligations
    raw = evidence.canonical_bytes(manifest)
    receipt = _replay(root, raw, expected)
    assert receipt["status"] == "PASS", receipt
    assert receipt["counts"]["expected"] == 135
    assert receipt["counts"]["passed"] == 135
    assert len(receipt["memberships"]) == 45
    assert all(row["status"] == "PASS" for row in receipt["memberships"])


def test_caller_authored_pass_field_is_not_evidence(tmp_path: Path) -> None:
    root, manifest, _ = _fixture(tmp_path)
    manifest["status"] = "PASS"
    raw = evidence.canonical_bytes(manifest)
    receipt = _replay(root, raw)
    assert receipt["status"] == "FAIL"
    assert "MANIFEST_CONTRACT_REJECTED" in receipt["invalidators"]
    assert receipt["evidence_digest"] is None


def test_digest_shaped_value_must_match_selected_bytes(tmp_path: Path) -> None:
    root, manifest, _ = _fixture(tmp_path)
    source = next(row for row in manifest["files"] if row["role"] == "SOURCE")
    source["sha256"] = "sha256:" + "0" * 64
    raw = evidence.canonical_bytes(manifest)
    receipt = _replay(root, raw)
    assert receipt["status"] == "FAIL"
    assert "SELECTED_FILE_DIGEST_MISMATCH" in receipt["invalidators"]


@pytest.mark.parametrize(
    "mutation, invalidator",
    [
        ("unknown", "UNKNOWN_OBLIGATION"),
        ("duplicate", "DUPLICATE_OBLIGATION_CASE"),
        ("substituted", "OBLIGATION_CASE_KIND_DIFFERS"),
        ("unmapped", "REQUIRED_OBLIGATION_CASE_UNMAPPED"),
        ("outside", "MANIFEST_PATH_INVALID"),
        ("recursive", "RECURSIVE_SELF_POLISH_TEST_REFUSED"),
    ],
)
def test_unknown_duplicate_unmapped_and_unsafe_selections_are_refused(
    tmp_path: Path, mutation: str, invalidator: str,
) -> None:
    root, manifest, _ = _fixture(tmp_path)
    expected = dict(EXPECTED)
    if mutation == "unknown":
        manifest["obligations"][0]["obligation_id"] = "tier1.unselected"
    elif mutation == "duplicate":
        manifest["obligations"][1]["case_kind"] = "POSITIVE"
    elif mutation == "substituted":
        manifest["obligations"][1]["case_kind"] = "PASS"
    elif mutation == "unmapped":
        manifest["obligations"].pop()
    elif mutation == "outside":
        manifest["files"][0]["path"] = "../outside.py"
        manifest["files"].sort(key=lambda row: row["path"])
    else:
        test_file = next(row for row in manifest["files"] if row["role"] == "TEST")
        test_file["path"] = evidence.RECURSIVE_TEST_PATH
        manifest["files"].sort(key=lambda row: row["path"])
    raw = evidence.canonical_bytes(manifest)
    receipt = _replay(root, raw, expected)
    assert receipt["status"] == "FAIL"
    assert invalidator in receipt["invalidators"]


@pytest.mark.parametrize("missing", ["NEGATIVE", "UNKNOWN"])
def test_negative_and_unknown_case_denominators_are_mandatory(
    tmp_path: Path, missing: str,
) -> None:
    root, _, raw = _fixture(tmp_path)
    expected = {
        "tier1.complete": tuple(
            case_kind for case_kind in evidence.CASE_KIND_ORDER
            if case_kind != missing
        ),
    }
    receipt = _replay(root, raw, expected)
    assert receipt["status"] == "FAIL"
    assert "OBLIGATION_DENOMINATOR_INVALID" in receipt["invalidators"]


def _trace(nodes: list[str], *, replacement: str | None = None,
           skipped: bool = False, exitstatus: int = 0) -> bytes:
    collected = list(nodes)
    if replacement is not None:
        collected[-1] = replacement
    reports = []
    for node in collected:
        reports.extend([
            {"nodeid": node, "when": "setup", "outcome": "passed", "wasxfail": None},
            {"nodeid": node, "when": "call",
             "outcome": "skipped" if skipped and node == collected[-1] else "passed",
             "wasxfail": "declared xfail" if skipped and node == collected[-1] else None},
            {"nodeid": node, "when": "teardown", "outcome": "passed", "wasxfail": None},
        ])
    return evidence.canonical_bytes({
        "schema_version": evidence.TRACE_SCHEMA,
        "collected": collected,
        "reports": reports,
        "exitstatus": exitstatus,
    })


def _junit(count: int, *, skipped: bool = False) -> bytes:
    cases = []
    for index in range(count):
        child = '<skipped type="pytest.xfail" />' if skipped and index == count - 1 else ""
        cases.append(f'<testcase classname="test_contract" name="test_{index}">{child}</testcase>')
    return (
        f'<testsuites><testsuite tests="{count}" failures="0" errors="0" '
        f'skipped="{1 if skipped else 0}">{"".join(cases)}</testsuite></testsuites>'
    ).encode("utf-8")


def _fake_completed_run(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
    *,
    replacement: str | None = None,
    skipped: bool = False,
    mutate_source: bool = False,
    returncode: int = 0,
) -> None:
    def run(argv, **kwargs):
        assert argv[:3] == [sys.executable, "-m", "pytest"]
        assert "--noconftest" in argv and "no:cacheprovider" in argv
        assert kwargs["cwd"] == root and kwargs["check"] is False
        assert kwargs["env"]["PYTHONDONTWRITEBYTECODE"] == "1"
        assert kwargs["env"]["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
        separator = argv.index("--")
        nodes = argv[separator + 1:]
        Path(kwargs["env"]["VSTD_SELF_POLISH_TRACE"]).write_bytes(
            _trace(nodes, replacement=replacement, skipped=skipped,
                   exitstatus=returncode),
        )
        junit_path = Path(argv[argv.index("--junitxml") + 1])
        junit_path.write_bytes(_junit(len(nodes), skipped=skipped))
        if mutate_source:
            (root / "src" / "specimen.py").write_text(
                "def bounded_value():\n    return 8\n", encoding="utf-8", newline="\n",
            )
        return subprocess.CompletedProcess(argv, returncode)

    monkeypatch.setattr(evidence.subprocess, "run", run)


def test_wrong_reason_zero_exit_cannot_become_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, raw = _fixture(tmp_path)
    _fake_completed_run(
        monkeypatch, root,
        replacement="tests/test_contract.py::test_unselected_but_green",
    )
    receipt = _replay(root, raw)
    assert receipt["status"] == "FAIL"
    assert "PYTEST_COLLECTION_MISMATCH" in receipt["invalidators"]
    assert "PYTEST_UNSELECTED_RESULT" in receipt["invalidators"]
    assert [row["status"] for row in receipt["memberships"]].count("UNKNOWN") == 1
    assert all(row["status"] != "PASS" for row in receipt["memberships"])


def test_skip_and_xfail_are_refused_even_with_zero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, raw = _fixture(tmp_path)
    _fake_completed_run(monkeypatch, root, skipped=True)
    receipt = _replay(root, raw)
    assert receipt["status"] == "FAIL"
    assert receipt["counts"]["skipped"] == 1
    assert receipt["counts"]["xfailed"] == 1
    assert "PYTEST_XFAIL_REFUSED" in receipt["invalidators"]
    assert "JUNIT_SKIP_OR_XFAIL_REFUSED" in receipt["invalidators"]


def test_selected_source_change_during_run_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, raw = _fixture(tmp_path)
    _fake_completed_run(monkeypatch, root, mutate_source=True)
    receipt = _replay(root, raw)
    assert receipt["status"] == "FAIL"
    assert "SELECTED_SOURCE_STALE_AFTER_REPLAY" in receipt["invalidators"]


def test_nonzero_run_is_refused_even_when_selected_outcomes_look_green(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, raw = _fixture(tmp_path)
    _fake_completed_run(monkeypatch, root, returncode=1)
    receipt = _replay(root, raw)
    assert receipt["status"] == "FAIL"
    assert "PYTEST_NONZERO_EXIT" in receipt["invalidators"]


def test_output_overflow_is_unknown_not_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, raw = _fixture(tmp_path)

    def overflow(argv, **kwargs):
        kwargs["stdout"].write(b"x" * (evidence.MAX_OUTPUT_BYTES + 1))
        kwargs["stdout"].flush()
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(evidence.subprocess, "run", overflow)
    receipt = _replay(root, raw)
    assert receipt["status"] == "UNKNOWN"
    assert "PYTEST_OUTPUT_CAPACITY_EXHAUSTED" in receipt["invalidators"]


def test_zero_exit_without_trace_and_junit_is_fail_not_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, raw = _fixture(tmp_path)
    monkeypatch.setattr(
        evidence.subprocess,
        "run",
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0),
    )
    receipt = _replay(root, raw)
    assert receipt["status"] == "FAIL"
    assert "PYTEST_EVIDENCE_MISSING" in receipt["invalidators"]


def test_timeout_is_unknown_not_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, raw = _fixture(tmp_path)

    def timeout(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(evidence.subprocess, "run", timeout)
    receipt = _replay(root, raw)
    assert receipt["status"] == "UNKNOWN"
    assert "PYTEST_TIME_BOUND_EXHAUSTED" in receipt["invalidators"]
    assert receipt["polished"] is False
