#!/usr/bin/env python3
"""Terminology: Verifier Standard (VSTD).

Keep the VSTD-NAMESPACE closed.

The namespace is `VSTD` plus sixteen objects and nothing else.  An ALL-CAPS
identifier is a claim to be one of them, so a name whose head is not in the set
is squatting: it takes a coordinate in a space it was never admitted to, and --
because no real tier is available to a non-object -- it reaches for the zero
tier the grid does not have.  Implementation identifiers belong in lowercase
`verifier-*`, where they collide with nothing.

Nothing enforced this before, and 137 names in 59 invented heads had accumulated
by v2.0.0.  Run with no arguments; a non-zero exit names every offender.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: The closed set.  `VSTD` is the base abstract; the rest are the sixteen objects.
OBJECTS: tuple[str, ...] = (
    "GRAPH", "ENV", "DATA", "BENCH", "HYPER", "MODEL", "SIM", "HARNESS",
    "AGENT", "BOT", "ACTOR", "ROLE", "COLLECTIVE", "IDENTITY", "HUMAN", "OWNER",
)

#: Names that keep a VSTD- spelling, each with the reason it may.  A name is not
#: added here to make the gate pass; it is added when rewriting it would make a
#: statement false.
EXCEPTIONS: dict[str, str] = {
    "VSTD-NAMESPACE": "the name of the space itself, not a member of it",
    "VSTD-NAMESPACE-1.1": "the published example of an identifier that does not parse",
    "VSTD-HUMAN-ACCEPTANCE": "acceptance-comment keyword parsed by scripts/check_pr_policy.py",
    "VSTD-INDIVIDUAL": "historical note: the object renamed to VSTD-ROLE on 2026-09-21",
    "VSTD-Conformant": "prose adjective, not an identifier",
    "VSTD-2-near-miss": "reject-path fixture: a VSTD-shaped identifier that must not resolve",
    "VSTD-5-DRAFT": "reject-path fixture: a VSTD-shaped identifier that must not resolve",
    "VSTD-SOMETHING-1": "reject-path fixture: an unrecognised schema_version",
    "VSTD-ZK-EXPERIMENT-0.1": (
        "the profile label proven inside examples/zizk_artifact_first/risc0/recorded-proof; "
        "renaming it would claim a proof was run over a label it was not"
    ),
}

#: Heads that are neither admitted nor evicted, because the question is open.
#: A name sits here only while a decision is outstanding, and the gate reports it
#: on every pass so the wait stays visible instead of going quiet.  This is not a
#: second exception list: a head leaves this table by being admitted to OBJECTS or
#: by being rewritten to lowercase, never by being forgotten.
PENDING: dict[str, str] = {
    "TRAIN": (
        "absent from the sixteen objects, yet present as 35 catalogued obligations "
        "across six tiers; it has no CHECKS entry and no adapter, so no certificate "
        "over it can be produced. Admit it as a seventeenth object or evict it "
        "-- awaiting Tyler, 2026-09-22"
    ),
}

#: CHANGELOG entries at or below this heading record what shipped under the old
#: names.  Rewriting them would falsify released history.
SHIPPED_HISTORY = ("CHANGELOG.md", "## 1.5.0 - 2026-09-18")

_TOKEN = re.compile(r"VSTD-[A-Za-z0-9][A-Za-z0-9.]*(?:-[A-Za-z0-9][A-Za-z0-9.]*)*")
_BASE_TIER = re.compile(r"[1-5](\.[0-9]+)?$")
_OBJECT_TAIL = re.compile(r"(-([1-6](\.([0-9]+|m))?|N|[1-5]\.\.[1-5]))?$")


def admissible(token: str) -> bool:
    """True when `token` is a name the VSTD-NAMESPACE actually contains."""

    if token in EXCEPTIONS:
        return True
    if token == "VSTD":            # the base abstract, bare
        return True
    rest = token[len("VSTD-"):]
    if rest[:1].islower():          # VSTD-bound, VSTD-facing: hyphenated prose
        return True
    if rest in ("N", "1..4", "1..5", "2..5"):
        return True
    if _BASE_TIER.fullmatch(rest):  # VSTD-1 .. VSTD-5, the base abstract's own tiers
        return True
    for name in (*OBJECTS, *PENDING):
        if rest.startswith(name) and _OBJECT_TAIL.fullmatch(rest[len(name):]):
            return True
    return False


def offenders() -> list[tuple[str, int, str]]:
    listed = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files"], capture_output=True, text=True, check=True
    ).stdout.split("\n")
    found: list[tuple[str, int, str]] = []
    for relative in filter(None, listed):
        path = ROOT / relative
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if relative == SHIPPED_HISTORY[0]:
            text = text.split(SHIPPED_HISTORY[1])[0]
        for number, line in enumerate(text.splitlines(), start=1):
            for match in _TOKEN.finditer(line):
                token = match.group(0).rstrip(".-")
                for suffix in (".md", ".html", ".json", ".py", ".txt"):
                    token = token[: -len(suffix)] if token.endswith(suffix) else token
                if not admissible(token):
                    found.append((relative, number, token))
    return found


def main() -> int:
    found = offenders()
    if not found:
        print(
            f"[NAMESPACE CLOSURE] PASS: the VSTD-NAMESPACE holds VSTD and "
            f"{len(OBJECTS)} objects; no name outside it claims a VSTD- coordinate."
        )
        for name, reason in PENDING.items():
            print(f"[NAMESPACE CLOSURE] UNDECIDED: VSTD-{name} -- {reason}")
        return 0
    print(f"[NAMESPACE CLOSURE] FAIL: {len(found)} name(s) outside the closed set:")
    for relative, number, token in found:
        print(f"  {relative}:{number}: {token}")
    print(
        "\nThe VSTD-NAMESPACE is VSTD plus "
        + ", ".join(OBJECTS)
        + ".\nAn implementation identifier belongs in lowercase verifier-* instead."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
