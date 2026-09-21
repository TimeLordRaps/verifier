"""Terminology: command-line interface (CLI); Verifier Standard (VSTD);
JavaScript Object Notation (JSON).

Accessibility surface: a guided entry point and plain-language artifact reading.

Two commands exist here, and they share one purpose: make the runtime usable
without first reading the specification.

``vstd start``    answers "what do I run first?" for a newcomer.
``vstd explain``  answers "what does this artifact actually say?" for anyone
                  holding a receipt or certificate.

Both emit either prose for a person or ``--json`` for a program, from the same
computed structure, so a human and an assistant reading the same artifact are
never told different things.

Neither command evaluates evidence, admits a mechanism, or changes a verdict.
``explain`` restates a stored result in plain language; it never upgrades
``UNKNOWN`` into anything else. It does exit on the stored verdict, following
the usual PASS 0 / FAIL 1 / UNKNOWN 2 convention, so a program reading the exit
code and a person reading the text are told the same thing.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

# Steps are ordered: each one is runnable once the ones above it have been.
_STEPS: tuple[dict[str, str], ...] = (
    {
        "id": "demo",
        "title": "See the runtime refuse a forged artifact",
        "why": "Proves the checks actually discriminate, before you trust any output.",
        "command": "vstd demo",
    },
    {
        "id": "demo-adversarial",
        "title": "Watch a deliberately wrong artifact get rejected",
        "why": "The same run under a tampered input, so you can see the failure shape.",
        "command": "vstd demo --scenario wrong-artifact --json",
    },
    {
        "id": "plan",
        "title": "Read what a manifest would do, without running it",
        "why": "`run` executes a command without a sandbox; `plan` never executes.",
        "command": "vstd plan examples/generic_run/manifest.json --json",
    },
    {
        "id": "run",
        "title": "Produce your first receipt",
        "why": "A receipt records an observed execution and its canonical digest.",
        "command": "vstd run examples/generic_run/manifest.json --output ./my-receipt",
    },
    {
        "id": "validate",
        "title": "Check that receipt",
        "why": "Runs the implemented structural and digest checks.",
        "command": "vstd validate ./my-receipt",
    },
    {
        "id": "explain",
        "title": "Read the result in plain language",
        "why": "Says what was established, what was not, and precisely why.",
        "command": "vstd explain ./my-receipt/receipt.json",
    },
    {
        "id": "catalog",
        "title": "See the obligations a claim can be held to",
        "why": "The 47 object obligations, and which have a built-in checker.",
        "command": "vstd certification catalog",
    },
    {
        "id": "domain-catalog",
        "title": "See the eight executable domain adapters",
        "why": "DATA, ENV, BENCH, HYPER, MODEL, SIM, HARNESS and AGENT, with their check graphs.",
        "command": "vstd certification domain-catalog",
    },
)

_CONCEPTS: tuple[tuple[str, str], ...] = (
    ("PASS / FAIL / UNKNOWN",
     "UNKNOWN means the evidence was absent, not that the claim is false. "
     "It is never upgraded by a later success."),
    ("established",
     "One check's own evidence was sufficient AND nothing it depends on is missing."),
    ("depth",
     "The longest unbroken run of established checks counted from the first. "
     "A later check can be established while depth stays low."),
    ("conformance",
     "Domain certificates never establish an object profile on their own; "
     "that needs an explicit claim/evidence binding."),
)


def add_accessibility_parsers(subparsers: argparse._SubParsersAction) -> None:
    """Register ``start`` and ``explain`` on the root parser."""
    start = subparsers.add_parser(
        "start",
        help="Show the shortest guided path from nothing to a checked result.",
        description="Print an ordered, copy-pasteable path through the runtime. "
                    "Runs nothing and writes nothing.",
    )
    start.add_argument("--json", action="store_true",
                       help="Emit the same path as a machine-readable task list.")

    explain = subparsers.add_parser(
        "explain",
        help="Describe a receipt or certificate in plain language.",
        description="Restate a stored result: what was established, what was not, "
                    "and exactly why. Never re-evaluates evidence. Exits on the "
                    "stored verdict: 0 PASS, 1 FAIL, 2 UNKNOWN.",
    )
    explain.add_argument("path", help="A receipt or certificate JSON file.")
    explain.add_argument("--json", action="store_true",
                         help="Emit the same explanation as structured data.")


# --------------------------------------------------------------------------
# start
# --------------------------------------------------------------------------

_GUIDES = ("docs/QUICKSTART.md", "docs/NEWCOMER_GUIDE.md")


def start_report() -> dict[str, Any]:
    """Return the guided path. Pure data, so prose and JSON cannot disagree."""
    return {
        "schema_version": "VSTD-START-1",
        "purpose": "Ordered path from an installed package to a checked result.",
        "steps": [dict(step, order=i) for i, step in enumerate(_STEPS, 1)],
        "concepts": [{"term": t, "meaning": m} for t, m in _CONCEPTS],
        "guides": list(_GUIDES),
        "next": "vstd explain <path-to-json>",
        "boundary": "This command runs nothing and writes nothing.",
    }


def _print_start(report: dict[str, Any]) -> None:
    print("VSTD — start here")
    print()
    print("Each step is runnable on its own. Run them in order the first time.")
    print()
    for step in report["steps"]:
        print(f"  {step['order']}. {step['title']}")
        print(f"     why:  {step['why']}")
        print(f"     run:  {step['command']}")
        print()
    print("Words that do not mean what you might assume:")
    for concept in report["concepts"]:
        print(f"  {concept['term']:<22} {concept['meaning']}")
    print()
    print("Full guides:   " + ", ".join(report["guides"]))
    print("Explain any result:  " + report["next"])


# --------------------------------------------------------------------------
# explain
# --------------------------------------------------------------------------

def _outcome_reason(row: dict[str, Any]) -> str:
    """Best available human reason for one check or obligation row."""
    evaluation = row.get("evaluation")
    if isinstance(evaluation, dict):
        detail = evaluation.get("details")
        if isinstance(detail, str) and detail:
            return detail
    reason = row.get("reason")
    return reason if isinstance(reason, str) and reason else "no reason recorded"


def _explain_rows(rows: dict[str, Any], *, outcome_of) -> list[dict[str, Any]]:
    explained = []
    for coordinate, row in rows.items():
        blocked = [b for b in row.get("blocked_by", []) if b]
        established = bool(row.get("established"))
        outcome = outcome_of(row)
        reason = _outcome_reason(row)
        if established:
            meaning = "established"
        elif blocked:
            meaning = "held back by " + ", ".join(blocked)
        elif outcome == "FAIL":
            meaning = f"refuted by its own evidence: {reason}"
        else:
            meaning = "not established: " + reason
        explained.append({
            "coordinate": coordinate,
            "name": row.get("name") or row.get("proposition") or "",
            "outcome": outcome,
            "established": established,
            "blocked_by": blocked,
            "reason": reason,
            "meaning": meaning,
        })
    return explained


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def _next_action(unresolved: list[dict[str, Any]], *, assess: str, replay: str) -> str:
    """The single most useful next command, phrased for the actual obstacle.

    A refutation and a missing input need opposite responses: supplying more
    evidence does not answer a FAIL, and re-reading the claim does not answer
    an absent input.
    """
    if not unresolved:
        return f"Everything here is established. Replay it with `{replay}`."
    first = unresolved[0]
    if first["outcome"] == "FAIL":
        return (
            f"{first['coordinate']} is refuted by its own evidence "
            f"({first['reason']}). Supplying more evidence will not "
            "clear it — either the claim or the artifact has to change."
        )
    if first["blocked_by"]:
        root = first["blocked_by"][0]
        return (
            f"{first['coordinate']} cannot be reached until {root} is "
            f"established. Start at {root}, then re-run `{assess}`."
        )
    return (
        f"Supply evidence for {first['coordinate']} ({first['reason']}), "
        f"then re-run `{assess}`."
    )


def _prefix_note(rows: list[dict[str, Any]], prefix: int, noun: str) -> str | None:
    """Explain the common surprise: something established past the counted prefix.

    ``prefix`` is the length of the unbroken established run counted from the
    first row. Anything established after the first gap does not raise it.
    """
    established = [r for r in rows if r["established"]]
    if len(established) <= prefix:
        return None
    beyond = [r["coordinate"] for r in established[prefix:]]
    first_gap = next((r["coordinate"] for r in rows if not r["established"]), None)
    return (
        f"{_plural(len(established), noun)} are established but the counted run "
        f"stops at {prefix}. It counts only the unbroken run from the first "
        f"{noun}, and {first_gap} breaks it. "
        f"{', '.join(beyond)} still {'holds' if len(beyond) == 1 else 'hold'} on "
        f"their own evidence — they are simply past the gap."
    )


def _explain_domain(cert: dict[str, Any]) -> dict[str, Any]:
    result = cert["result"]
    rows = _explain_rows(result.get("checks", {}),
                         outcome_of=lambda r: r.get("evaluation", {}).get("outcome", "UNKNOWN"))
    depth = int(result.get("domain_depth", 0))
    domain = rows[0]["coordinate"].split(".")[0] if rows else "?"
    unresolved = [r for r in rows if not r["established"]]
    return {
        "kind": "domain certificate",
        "subject": f"{domain} — {result.get('scope', '')}",
        "status": result.get("status", "UNKNOWN"),
        "headline": (
            f"{len([r for r in rows if r['established']])} of {len(rows)} {domain} "
            f"checks established; depth {depth}."
        ),
        "rows": rows,
        "depth": depth,
        "depth_note": _prefix_note(rows, depth, "check"),
        "conformance_note": (
            "Object profile conformance is "
            f"{result.get('object_profile_conformance', 'NOT_ESTABLISHED')}. "
            "A domain certificate never establishes an object profile by itself."
        ),
        "next": _next_action(
            unresolved,
            assess="vstd certification domain-assess",
            replay="vstd certification domain-check",
        ),
    }


def _explain_grounded(cert: dict[str, Any]) -> dict[str, Any]:
    result = cert["result"]
    rows = _explain_rows(result.get("obligations", {}),
                         outcome_of=lambda r: r.get("outcome", "UNKNOWN"))
    profiles = result.get("profiles", {})
    # certified_profile_depth counts COMPLETE profiles, not established
    # obligations. Reporting it as an obligation count is the single easiest
    # way to misread this certificate, so name both separately.
    complete = int(result.get("certified_profile_depth", 0))
    established = len([r for r in rows if r["established"]])

    summaries, notes = [], []
    for key in sorted(profiles, key=lambda k: (len(k), k)):
        profile = profiles[key]
        rows_here = [r for r in rows if r["coordinate"].split(".")[0] == key]
        blocking = [b for b in profile.get("blocking_obligations", []) if b]
        summaries.append({
            "profile": key,
            "name": profile.get("name", ""),
            "obligation_count": profile.get("obligation_count", len(rows_here)),
            "established_prefix": profile.get("established_prefix", 0),
            "complete": bool(profile.get("cumulative_established")),
            "blocking": blocking,
        })
        note = _prefix_note(rows_here, int(profile.get("established_prefix", 0)), "obligation")
        if note:
            notes.append(f"VSTD-{key}: {note}")

    unresolved = [r for r in rows if not r["established"]]
    return {
        "kind": "grounded object certificate",
        "subject": "object profile" + ("s " if len(profiles) != 1 else " ")
                   + ", ".join(sorted(profiles)),
        "status": result.get("certification_status", "NOT_ESTABLISHED"),
        "headline": (
            f"{established} of {len(rows)} obligations established; "
            f"{_plural(complete, 'profile')} complete."
        ),
        "rows": rows,
        "profiles": summaries,
        "depth": complete,
        "depth_note": " ".join(notes) or None,
        "conformance_note": (
            "`certified profile depth` counts whole profiles, not obligations. "
            "A profile is complete only when every one of its obligations is "
            "established, so a single UNKNOWN leaves the whole profile UNKNOWN."
        ),
        "next": _next_action(
            unresolved,
            assess="vstd certification assess",
            replay="vstd certification check",
        ),
    }


def _explain_receipt(receipt: dict[str, Any], path: Path) -> dict[str, Any]:
    """Explain a run receipt: what it records, and what it does not decide.

    A receipt is the first artifact most people produce, so this is the
    highest-traffic explanation. It carries no verdict -- `vstd validate`
    produces that -- and the point most often misread is that a *declared*
    reproducibility ceiling is not a *demonstrated* level.
    """
    execution = receipt.get("execution") or {}
    repro = receipt.get("reproducibility") or {}
    inputs = receipt.get("inputs") or []
    outputs = receipt.get("outputs") or []
    limits = [l for l in (receipt.get("claim_limitations") or []) if l]

    outcome = str(execution.get("outcome", "UNKNOWN"))
    exit_code = execution.get("exit_code")
    declared = repro.get("declared_ceiling")
    demonstrated = repro.get("highest_demonstrated_level")

    rows = [
        {"coordinate": "claim", "name": "what this receipt is about",
         "outcome": "RECORDED", "established": True, "blocked_by": [],
         "reason": str(receipt.get("claim_title") or "no claim title recorded"),
         "meaning": str(receipt.get("claim_title") or "no claim title recorded")},
        {"coordinate": "execution", "name": "the observed run",
         "outcome": outcome, "established": outcome == "COMPLETED", "blocked_by": [],
         "reason": f"exit code {exit_code}",
         "meaning": f"{outcome.lower()}, exit code {exit_code}, "
                    f"{execution.get('elapsed_ms', 0):.0f} ms on "
                    f"{execution.get('platform_system', 'an unrecorded platform')}"},
        {"coordinate": "recorded", "name": "digested files",
         "outcome": "RECORDED", "established": bool(inputs or outputs), "blocked_by": [],
         "reason": f"{_plural(len(inputs), 'input')}, {_plural(len(outputs), 'output')}",
         "meaning": f"{_plural(len(inputs), 'input')} and "
                    f"{_plural(len(outputs), 'output')} digested; receipt digest "
                    f"{str(receipt.get('canonical_digest', ''))[:12] or 'absent'}"},
        {"coordinate": "reproducible", "name": "reproducibility",
         "outcome": "DECLARED" if demonstrated is None else "DEMONSTRATED",
         "established": demonstrated is not None, "blocked_by": [],
         "reason": f"declared ceiling {declared}, highest demonstrated {demonstrated}",
         "meaning": (f"{declared} is declared as the ceiling; nothing has been "
                     f"demonstrated yet" if demonstrated is None else
                     f"{demonstrated} demonstrated against a {declared} ceiling")},
    ]

    return {
        "kind": "run receipt",
        "subject": str(receipt.get("receipt_id") or path.name),
        "status": outcome,
        "headline": str(receipt.get("claim_statement")
                        or "This receipt records an execution."),
        "rows": rows,
        "limitations": limits,
        "depth": None,
        "depth_note": None,
        "conformance_note": (
            "A receipt records what was observed; it is not a verdict. "
            + ("A declared reproducibility ceiling is what the receipt is willing "
               "to be held to, not something it has shown. "
               if demonstrated is None else "")
            + "Run `vstd validate` to get a checked result."
        ),
        "next": (f"Run `vstd validate {path.parent}` to check its integrity, then "
                 f"`vstd reproduce {path.parent} --rerun` to actually demonstrate "
                 f"the declared {declared} ceiling." if demonstrated is None else
                 f"Run `vstd reproduce {path.parent} --rerun` to repeat it."),
    }


def _explain_other(document: dict[str, Any], path: Path) -> dict[str, Any]:
    version = document.get("schema_version")
    return {
        "kind": "receipt",
        "subject": str(version or "unrecognized document"),
        "status": str(document.get("status", "no verdict recorded")),
        "headline": (
            f"{path.name} declares schema `{version}`."
            if version else
            f"{path.name} has no `schema_version`, so it is not a VSTD artifact."
        ),
        "rows": [],
        "depth": None,
        "depth_note": None,
        "conformance_note": None,
        "next": (
            f"Run `vstd validate {path.parent}` to check it, or "
            "`vstd inspect` to report its VSTD-3 content."
            if version else
            "Point `vstd explain` at a receipt.json or certificate.json."
        ),
    }


# The guided path hands `vstd validate` a directory at step five, so a reader
# naturally hands `vstd explain` the same directory at step six. Accepting only
# the inner file would make the two steps disagree for no reason.
_IN_DIRECTORY = ("receipt.json", "certificate.json")


def resolve_explain_target(path: Path) -> Path | None:
    """Return the artifact to explain, or None if there is nothing to read."""
    path = path.resolve()
    if path.is_file():
        return path
    if path.is_dir():
        for name in _IN_DIRECTORY:
            if (path / name).is_file():
                return path / name
    return None


def explain_report(path: Path) -> dict[str, Any]:
    """Return a structured explanation of one stored artifact."""
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path} does not contain a JSON object")
    version = document.get("schema_version")
    if version == "VSTD-DOMAIN-CERTIFICATION-1":
        report = _explain_domain(document)
    elif version == "VSTD-GROUNDED-CERTIFICATION-1":
        report = _explain_grounded(document)
    elif version == "VSTD-1" and document.get("receipt_kind"):
        report = _explain_receipt(document, path)
    else:
        report = _explain_other(document, path)
    report["schema_version"] = "VSTD-EXPLANATION-1"
    # A document with no `schema_version` is not a VSTD artifact at all. That is
    # the same class of mistake as pointing at a missing file, so the caller
    # reports it the same way rather than as a successful read of nothing.
    report["recognized"] = bool(version)
    report["source"] = str(path)
    report["boundary"] = (
        "Restated from the stored result. No evidence was re-evaluated and no "
        "outcome was changed."
    )
    return report


# A stored verdict maps onto the CLI convention PASS 0, FAIL 1, UNKNOWN 2, so a
# program chaining `vstd explain ... && ...` cannot read success out of a
# refutation that the printed text calls FAIL. A document carrying no verdict
# has nothing to propagate and reports a successful read.
_EXIT_FOR_STATUS = {
    "PASS": 0, "ESTABLISHED": 0,
    "FAIL": 1, "REFUTED": 1,
    "UNKNOWN": 2, "NOT_ESTABLISHED": 2,
}


def explanation_exit_code(report: dict[str, Any]) -> int:
    """Exit code for an explained artifact: its own verdict, never a new one."""
    return _EXIT_FOR_STATUS.get(str(report.get("status", "")).upper(), 0)


def _print_explain(report: dict[str, Any]) -> None:
    print(f"{report['kind']}: {report['subject']}")
    print(f"status: {report['status']}")
    print()
    print(report["headline"])
    if report["rows"]:
        print()
        width = max(len(r["coordinate"]) for r in report["rows"])
        for row in report["rows"]:
            mark = "ok  " if row["established"] else "--  "
            print(f"  {mark}{row['coordinate']:<{width}}  {row['outcome']:<8} {row['meaning']}")
    if report.get("limitations"):
        print()
        print("what it explicitly does not claim:")
        for limitation in report["limitations"]:
            print(f"  - {limitation}")
    if report.get("depth_note"):
        print()
        print("why the depth is what it is:")
        print(f"  {report['depth_note']}")
    if report.get("conformance_note"):
        print()
        print(f"boundary: {report['conformance_note']}")
    print()
    print(f"next: {report['next']}")


# --------------------------------------------------------------------------

def handle_accessibility_command(args: argparse.Namespace) -> int:
    """Dispatch ``start`` and ``explain``. Returns a process exit code."""
    if args.command == "start":
        report = start_report()
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            _print_start(report)
        return 0

    path = resolve_explain_target(Path(args.path))
    if path is None:
        given = Path(args.path).resolve()
        print(f"[FAIL] Nothing to explain at: {given}")
        print("       `vstd explain` reads a receipt or certificate JSON file, or a")
        print("       directory containing one. Try `vstd start` if you have none yet.")
        return 1
    try:
        report = explain_report(path)
    except (ValueError, json.JSONDecodeError) as error:
        print(f"[FAIL] Could not read {path}: {error}")
        print("       `vstd explain` expects a JSON object, such as a receipt.json")
        print("       or a certificate.json. Try `vstd start`.")
        return 1
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_explain(report)
    if not report["recognized"]:
        return 1
    return explanation_exit_code(report)
