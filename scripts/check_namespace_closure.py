#!/usr/bin/env python3
"""Terminology: Verifier Standard (VSTD).

Keep the VSTD-NAMESPACE closed.

The namespace is the base abstract `VSTD` plus seventeen objects and nothing else.
ALL-CAPS is the namespace marker, so an object is spelled by its bare name --
`DATA`, `GRAPH-1`, `OWNER-4.5` -- and the `VSTD-` prefix survives only where a
bare name would say nothing (`VSTD-1` through `VSTD-6`, the base abstract's own
tiers) or would be ambiguous (`VSTD-NAMESPACE`, the name of the space itself).

Nothing enforced this before, and 137 names under 59 invented heads had
accumulated by v2.0.0.  Two checks run here:

  catalogue  every object the catalogue carries is one of the seventeen, or a
             named composition over them.  This is the load-bearing check: it
             reads the object set rather than prose, so a new name cannot enter
             by being written down somewhere.

  residue    no `VSTD-` prefix survives on anything but the tiers, the name of
             the space, and a short list of strings that merely contain an
             object name without referring to one.

Run with no arguments; a non-zero exit names every offender.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

#: The closed set.  `VSTD` is the base abstract; these are the seventeen objects.
OBJECTS: frozenset[str] = frozenset({
    "GRAPH", "ENV", "DATA", "BENCH", "HYPER", "MODEL", "SIM", "HARNESS",
    "AGENT", "BOT", "ACTOR", "ROLE", "COLLECTIVE", "IDENTITY", "HUMAN", "OWNER",
    "TOKEN",
})

#: Named compositions: expressible in the namespace without being members of it.
#: A composition is written *over* the objects, so admitting one as an object would
#: double-count what it is made of -- and the namespace would stop being a basis.
#: It is still catalogued, because a named composition nothing checks is just prose,
#: which is why the domain catalogue carries one entry more than the namespace does.
#: This is not a second exception list and it is not a waiting room: a head leaves
#: this table by being admitted to OBJECTS or by ceasing to be named, never by being
#: forgotten, and its definition here must say what it is composed of.
COMPOSITIONS: dict[str, str] = {
    "TRAIN": (
        "a training run is HYPER(VSTD, MODEL, DATA, ENV, SIM, BENCH) indexed by a "
        "GRAPH-1 recorded lineage, where VSTD is the model and training-loop "
        "algorithms and GRAPH-1 carries the order the data was consumed in. "
        "Catalogued as 35 obligations over six tiers, and the only *composed* domain "
        "entry -- it is grounded without being certifiable because "
        "it inherits a substrate from its operands, and has none of its own to "
        "adapt. Ruled 2026-09-22"
    ),
}

#: Strings that contain an object name without naming an object.  Each carries
#: the reason it survives; a test requires the reason to be there.
EXCEPTIONS: dict[str, str] = {
    "VSTD-NAMESPACE": "the name of the space itself; a bare NAMESPACE is ambiguous",
    "VSTD-NAMESPACE-1.1": "the published example of an identifier that does not parse",
    "VSTD-INDIVIDUAL": "historical note: the object renamed to ROLE on 2026-09-21",
    "VSTD-Conformant": "prose adjective, not an identifier",
    "VSTD-2-near-miss": "reject-path fixture: a VSTD-shaped identifier that must not resolve",
    "VSTD-5-DRAFT": "reject-path fixture: a VSTD-shaped identifier that must not resolve",
    "VSTD-SOMETHING-1": "reject-path fixture: an unrecognised schema_version",
    "VSTD-ZK-EXPERIMENT-0.1": (
        "the profile label proven inside examples/zizk_artifact_first/risc0/recorded-proof; "
        "renaming it would claim a proof was run over a label it was not"
    ),
}

#: CHANGELOG entries at or below this heading record what shipped under the old
#: names.  Rewriting them would falsify released history.
SHIPPED_HISTORY = ("CHANGELOG.md", "## 1.5.0 - 2026-09-18")

_RESIDUE = re.compile(r"VSTD-[A-Za-z0-9][A-Za-z0-9.]*(?:-[A-Za-z0-9][A-Za-z0-9.]*)*")
_BASE_TIER = re.compile(r"[1-6](\.[1-9][0-9]*)?$")
#: `VSTD-N`, `VSTD-1..5`, `VSTD-1..VSTD-6`: a range or placeholder over the base
#: abstract's own tiers, which is prose about the ladder rather than a name on it.
_TIER_RANGE = re.compile(r"(N|[1-6]\.\.(VSTD-)?[1-6])$")


def admissible(token: str) -> bool:
    """True when `token` is a VSTD- spelling the namespace still allows."""

    if token == "VSTD" or token in EXCEPTIONS:
        return True
    rest = token[len("VSTD-"):]
    if rest[:1].islower():              # VSTD-bound, VSTD-facing: hyphenated prose
        return True
    if _TIER_RANGE.fullmatch(rest):
        return True
    return bool(_BASE_TIER.fullmatch(rest))


def catalogue_offenders() -> list[str]:
    """Every object the catalogue carries must be one of the seventeen."""

    from verifier.core.profile_obligations import DOMAIN_OBJECTS

    return sorted(set(DOMAIN_OBJECTS) - OBJECTS - set(COMPOSITIONS))


def residue_offenders() -> list[tuple[str, int, str]]:
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
            for match in _RESIDUE.finditer(line):
                token = match.group(0).rstrip(".-")
                for suffix in (".md", ".html", ".json", ".py", ".txt"):
                    token = token[: -len(suffix)] if token.endswith(suffix) else token
                if not admissible(token):
                    found.append((relative, number, token))
    return found


def main() -> int:
    catalogue = catalogue_offenders()
    residue = residue_offenders()

    if catalogue:
        print(f"[NAMESPACE CLOSURE] FAIL: {len(catalogue)} object(s) outside the seventeen:")
        for name in catalogue:
            print(f"  the catalogue carries {name}")
    if residue:
        print(f"[NAMESPACE CLOSURE] FAIL: {len(residue)} VSTD- prefix(es) that should be bare:")
        for relative, number, token in residue:
            print(f"  {relative}:{number}: {token}")
    if catalogue or residue:
        print(
            "\nThe VSTD-NAMESPACE is VSTD plus "
            + ", ".join(sorted(OBJECTS))
            + ".\nALL-CAPS is the marker, so an object is spelled bare; the prefix"
            "\nsurvives only on VSTD-1..VSTD-6 and on VSTD-NAMESPACE itself."
            "\nAn implementation identifier belongs in lowercase verifier-*."
        )
        return 1

    print(
        f"[NAMESPACE CLOSURE] PASS: the VSTD-NAMESPACE holds VSTD and "
        f"{len(OBJECTS)} objects, each spelled bare; the prefix survives only on "
        f"VSTD-1..VSTD-6 and VSTD-NAMESPACE."
    )
    for name, definition in COMPOSITIONS.items():
        print(f"[NAMESPACE CLOSURE] COMPOSITION: {name} -- {definition}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
