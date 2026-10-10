"""The local release commands in AGENTS.md mirror the continuous integration (CI) jobs they cite."""

from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
INTEGRITY_JOB = "release-integrity"
REPRODUCIBILITY_JOB = "release-reproducibility"
COMPARE_MARKER = "scripts/release_artifacts.py compare"
INTEGRITY_MARKERS = (
    'pip install ".[release]"',
    "VERSION=",
    "scripts/release_artifacts.py",
    "-m twine check",
    "scripts/check_release_boundary.py",
)
NEWLINE = chr(10)
CONTINUATION = chr(92) + NEWLINE  # a backslash that ends a physical line
# The workflow writes under dist/ and AGENTS.md under /tmp. AGENTS.md also names the platform
# directories that the reproducibility job downloads.
SPELLINGS = (
    ("dist/release-integrity", "OUTPUT"),
    ("/tmp/vstd-release", "OUTPUT"),
    ("dist/ubuntu", "LINUX"),
    ("PATH_TO_LINUX_ARTIFACTS", "LINUX"),
    ("dist/windows", "WINDOWS"),
    ("PATH_TO_WINDOWS_ARTIFACTS", "WINDOWS"),
    ("dist/macos", "MACOS"),
    ("PATH_TO_MACOS_ARTIFACTS", "MACOS"),
)

# A synthetic workflow and document in the shape of the real ones, used to test the comparison.
WORKFLOW = {
    "jobs": {
        INTEGRITY_JOB: {
            "steps": [
                {"uses": "actions/checkout"},
                {"run": 'python -m pip install ".[release]"'},
                {
                    "run": NEWLINE.join(
                        [
                            "python scripts/release_artifacts.py build --ref HEAD "
                            + CONTINUATION
                            + "  --output-dir dist/release-integrity",
                            "# a comment",
                            "echo a diagnostic that AGENTS.md need not repeat",
                        ]
                    )
                },
                {"run": "python -m twine check dist/release-integrity/*.whl"},
            ]
        },
        REPRODUCIBILITY_JOB: {
            "steps": [
                {
                    "run": NEWLINE.join(
                        [
                            "python scripts/release_artifacts.py compare dist/ubuntu dist/windows",
                            "python scripts/release_artifacts.py compare dist/ubuntu dist/macos",
                        ]
                    )
                }
            ]
        },
    }
}
DOCUMENT = NEWLINE.join(
    [
        "# Fixture",
        "",
        "An unrelated block, which is not tied to a job:",
        "",
        "```bash",
        "python scripts/release_artifacts.py source --ref HEAD --output-dir elsewhere",
        "```",
        "",
        "Local checks, mirroring one platform of the `release-integrity` job:",
        "",
        "```bash",
        'python -m pip install ".[release]"',
        "python scripts/release_artifacts.py build --ref HEAD "
        + CONTINUATION
        + "  --output-dir /tmp/vstd-release",
        "python -m twine check /tmp/vstd-release/*.whl",
        "```",
        "",
        "The `release-reproducibility` job compares the platforms:",
        "",
        "```bash",
        "python scripts/release_artifacts.py compare PATH_TO_LINUX_ARTIFACTS PATH_TO_WINDOWS_ARTIFACTS",
        "python scripts/release_artifacts.py compare PATH_TO_LINUX_ARTIFACTS PATH_TO_MACOS_ARTIFACTS",
        "```",
        "",
    ]
)


def _normalize(command: str) -> str:
    for spelled, canonical in SPELLINGS:
        command = command.replace(spelled, canonical)
    return " ".join(command.split())


def _commands(script: str) -> list[str]:
    """Return the commands of a shell script, with continued lines joined and comments dropped."""
    commands = []
    for line in script.replace(CONTINUATION, " ").splitlines():
        text = line.strip()
        if text and not text.startswith("#"):
            commands.append(text)
    return commands


def _workflow_commands(workflow: dict, job: str) -> list[str]:
    commands: list[str] = []
    for step in workflow["jobs"][job]["steps"]:
        if "run" in step:
            commands.extend(_commands(step["run"]))
    return commands


def _documented_commands(markdown: str, job: str) -> list[str]:
    """Return the commands in fenced blocks whose introducing paragraph names the job."""
    commands: list[str] = []
    paragraph: list[str] = []
    introducer = ""
    block: list[str] | None = None
    for line in markdown.splitlines():
        if line.lstrip().startswith("```"):
            if block is None:
                block = []
            else:
                if job in introducer:
                    commands.extend(_commands(NEWLINE.join(block)))
                block, paragraph, introducer = None, [], ""
        elif block is not None:
            block.append(line)
        elif line.strip():
            paragraph.append(line)
            introducer = " ".join(paragraph)
        else:
            paragraph = []
    return commands


def _release_commands(commands: list[str], *, compare: bool) -> list[str]:
    selected = []
    for command in commands:
        if compare:
            wanted = COMPARE_MARKER in command
        else:
            wanted = COMPARE_MARKER not in command and any(
                marker in command for marker in INTEGRITY_MARKERS
            )
        if wanted:
            selected.append(_normalize(command))
    return selected


def _differences(expected: list[str], documented: list[str]) -> list[str]:
    problems = [f"missing from AGENTS.md: {c}" for c in expected if c not in documented]
    problems += [f"not in the workflow: {c}" for c in documented if c not in expected]
    if not problems and expected != documented:
        problems.append("same commands, different order or multiplicity")
    return problems


def _problems(workflow: dict, markdown: str, job: str, *, compare: bool) -> list[str]:
    expected = _release_commands(_workflow_commands(workflow, job), compare=compare)
    if not expected:
        return [f"the workflow job {job} lists no release commands to mirror"]
    documented = _release_commands(_documented_commands(markdown, job), compare=compare)
    return _differences(expected, documented)


def _real_problems(job: str, *, compare: bool) -> list[str]:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    return _problems(workflow, agents, job, compare=compare)


def test_agents_release_commands_mirror_the_release_integrity_job() -> None:
    assert _real_problems(INTEGRITY_JOB, compare=False) == []


def test_agents_comparison_commands_mirror_the_release_reproducibility_job() -> None:
    assert _real_problems(REPRODUCIBILITY_JOB, compare=True) == []


def test_a_document_that_mirrors_the_workflow_has_no_problems() -> None:
    assert _problems(WORKFLOW, DOCUMENT, INTEGRITY_JOB, compare=False) == []
    assert _problems(WORKFLOW, DOCUMENT, REPRODUCIBILITY_JOB, compare=True) == []


def test_drifted_documents_are_reported() -> None:
    twine = "python -m twine check /tmp/vstd-release/*.whl"
    drifts = {
        "different subcommand": ("release_artifacts.py build", "release_artifacts.py source"),
        "dropped command": (twine + NEWLINE, ""),
        "added command": (twine, twine + NEWLINE + twine.replace("*.whl", "*.zip")),
        "wrong platform pair": (
            "compare PATH_TO_LINUX_ARTIFACTS PATH_TO_MACOS_ARTIFACTS",
            "compare PATH_TO_LINUX_ARTIFACTS PATH_TO_WINDOWS_ARTIFACTS",
        ),
        "paragraph that no longer names the job": (
            "one platform of the `release-integrity` job",
            "one platform of the main job",
        ),
    }
    for name, (old, new) in drifts.items():
        drifted = DOCUMENT.replace(old, new)
        assert drifted != DOCUMENT, f"the {name} drift did not apply to the fixture"
        problems = _problems(WORKFLOW, drifted, INTEGRITY_JOB, compare=False)
        problems += _problems(WORKFLOW, drifted, REPRODUCIBILITY_JOB, compare=True)
        assert problems, f"the {name} drift was not reported"


def test_differences_report_missing_extra_and_misordered_commands() -> None:
    expected = ["one", "two"]
    assert _differences(expected, ["one", "two"]) == []
    assert _differences(expected, ["one"]) == ["missing from AGENTS.md: two"]
    assert _differences(expected, ["one", "two", "three"]) == ["not in the workflow: three"]
    assert _differences(expected, ["two", "one"]) == [
        "same commands, different order or multiplicity"
    ]
    assert _differences(expected, ["one", "two", "two"]) == [
        "same commands, different order or multiplicity"
    ]


def test_commands_join_continued_lines_and_skip_comments() -> None:
    script = NEWLINE.join(["# note", "python one " + CONTINUATION + "  --two", "", "python three"])
    assert [_normalize(command) for command in _commands(script)] == [
        "python one --two",
        "python three",
    ]


def test_a_block_is_tied_to_the_nearest_preceding_paragraph() -> None:
    naming = "Mirrors `release-integrity`:"
    tight = NEWLINE.join([naming, "```bash", "python a", "```", "python b", ""])
    spaced = NEWLINE.join([naming, "", "```bash", "python a", "```", ""])
    other = NEWLINE.join([naming, "", "A different paragraph.", "", "```bash", "python a", "```", ""])
    assert _documented_commands(tight, INTEGRITY_JOB) == ["python a"]
    assert _documented_commands(spaced, INTEGRITY_JOB) == ["python a"]
    assert _documented_commands(other, INTEGRITY_JOB) == []
    assert _documented_commands(spaced, REPRODUCIBILITY_JOB) == []
