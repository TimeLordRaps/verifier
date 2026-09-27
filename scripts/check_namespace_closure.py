#!/usr/bin/env python3
"""Keep Verifier Standard (VSTD) namespace admission and legacy spellings closed.

The current VSTD-NAMESPACE has 26 object kinds and eight general meta-tiers.
`VSTD` names the standard, not a current object kind. The older numbered-profile
catalogue has 19 domain kinds, plus separate VSTD and Graph axes whose historical
receipt coordinates and wire identifiers are not renamed by this gate.

ALL-CAPS is the object-name marker. A `VSTD-` prefix on a current object remains
invalid; historical `VSTD-1` through `VSTD-6` and the `VSTD-NAMESPACE` title
remain admissible lexical references. Admission checks names and tier enum
meanings, not per-object objective registration or certification.

Run with no arguments; a non-zero exit names every offender.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

#: Independent current specification inventory; compared with runtime ObjectKind.
OBJECTS: frozenset[str] = frozenset({
    "HUMAN", "ACTOR", "COLLECTIVE", "ROLE", "IDENTITY", "OWNER", "HARDWARE",
    "RECEIPT", "OBJECT", "GRAPH", "SPACE", "TIME", "EVENT", "ENV", "DATA",
    "VERIFIER", "BENCH", "ARCH", "TRAIN", "HYPER", "MODEL", "HARNESS",
    "AGENT", "SIM", "BOT", "TOKEN",
})

#: Earlier domain-object obligations retain exactly this nineteen-kind scope.
LEGACY_DOMAIN_OBJECTS: frozenset[str] = frozenset({
    "HUMAN", "ACTOR", "COLLECTIVE", "ROLE", "IDENTITY", "OWNER", "HARDWARE",
    "ENV", "DATA", "VERIFIER", "BENCH", "TRAIN", "HYPER", "MODEL",
    "HARNESS", "AGENT", "SIM", "BOT", "TOKEN",
})

#: General tier meanings, distinct from the retained numbered-profile catalogue.
CURRENT_TIERS: dict[int, str] = {
    1: "FACETS", 2: "DYNAMICS", 3: "STATICS", 4: "CLOSURE",
    5: "INDEPENDENCE", 6: "PRIVACY", 7: "CONSENT", 8: "GOVERNANCE",
}

#: Named compositions that are *not* members of the namespace.  Empty by ruling.
#: Being written over other objects was once taken to disqualify a name from
#: membership, on the grounds that the namespace would stop being a basis.  TRAIN was
#: admitted anyway on 2026-09-22: composition is a property an object has, not a
#: reason it is not one, and TRAIN carries a substrate of its own -- a checkpoint
#: inventory and a step trace -- which `verifier.domains.train` replays.  What TRAIN
#: is composed of is recorded in COMPOSITION_OF, which is where that fact belongs.
#: The table stays because the question can recur: a head enters only with a
#: definition saying what it is composed of, and leaves only by being admitted to
#: OBJECTS or by ceasing to be named, never by being forgotten.
COMPOSITIONS: dict[str, str] = {}

#: Strings that contain an object name without naming an object.  Each carries
#: the reason it survives; a test requires the reason to be there.
EXCEPTIONS: dict[str, str] = {
    "VSTD-NAMESPACE": "the name of the space itself; a bare NAMESPACE is ambiguous",
    "VSTD-NAMESPACE-1.1": "the published example of an identifier that does not parse",
    "VSTD-INDIVIDUAL": "historical note: the object renamed to ROLE on 2026-09-21",
    "VSTD-Conformant": "prose adjective, not an identifier",
    "VSTD-ENVIRONMENT-DEFINITION-0.1": "exact experimental environment record discriminator quoted for migration; not an admitted namespace object or native certificate",
    "VSTD-ENVIRONMENT-INSTANCE-0.1": "exact experimental environment record discriminator quoted for migration; not an admitted namespace object or native certificate",
    "VSTD-ENVIRONMENT-RUN-0.1": "exact experimental environment record discriminator quoted for migration; not an admitted namespace object or native certificate",
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
SOURCE_FEATURE_MANIFEST = "docs/PR_SOURCE_FEATURES.json"

_RESIDUE = re.compile(r"VSTD-[A-Za-z0-9][A-Za-z0-9.]*(?:-[A-Za-z0-9][A-Za-z0-9.]*)*")
_BASE_TIER = re.compile(r"[1-6](\.[1-9][0-9]*)?$")
#: `VSTD-N`, `VSTD-1..5`, `VSTD-1..VSTD-6`: a range or placeholder over the base
#: abstract's own tiers, which is prose about the ladder rather than a name on it.
_TIER_RANGE = re.compile(r"(N|[1-6]\.\.(VSTD-)?[1-6])$")


def admissible(token: str) -> bool:
    """True for a retained VSTD-prefixed lexical spelling, not object admission."""

    if token == "VSTD" or token in EXCEPTIONS:
        return True
    rest = token[len("VSTD-"):]
    if rest[:1].islower():              # VSTD-bound, VSTD-facing: hyphenated prose
        return True
    if _TIER_RANGE.fullmatch(rest):
        return True
    return bool(_BASE_TIER.fullmatch(rest))


def catalogue_offenders() -> list[str]:
    """An added legacy catalogue object needs an explicit migration decision."""

    from verifier.core.profile_obligations import DOMAIN_OBJECTS

    return sorted(set(DOMAIN_OBJECTS) - LEGACY_DOMAIN_OBJECTS - set(COMPOSITIONS))


def catalogue_missing() -> list[str]:
    """The retained 19-domain catalogue cannot silently lose a domain object."""
    from verifier.core.profile_obligations import DOMAIN_OBJECTS

    return sorted(LEGACY_DOMAIN_OBJECTS - set(DOMAIN_OBJECTS))


def current_namespace_offenders() -> list[str]:
    """Check the independent name inventory against admitted runtime kinds."""
    from verifier.core.namespace import ObjectKind

    runtime = {kind.value for kind in ObjectKind}
    return ([f"{name} missing from gate" for name in sorted(runtime - OBJECTS)]
            + [f"{name} absent from runtime" for name in sorted(OBJECTS - runtime)])


def current_tier_offenders() -> list[str]:
    """A tier name or number must not drift without a reviewed spec change."""
    from verifier.core.namespace import MetaTier

    runtime = {tier.value: tier.name for tier in MetaTier}
    return [f"tier {number}: expected {CURRENT_TIERS.get(number)}, runtime {runtime.get(number)}"
            for number in sorted(set(CURRENT_TIERS) | set(runtime))
            if CURRENT_TIERS.get(number) != runtime.get(number)]


def residue_offenders() -> list[tuple[str, int, str]]:
    listed = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files"], capture_output=True, text=True, check=True
    ).stdout.split("\n")
    found: list[tuple[str, int, str]] = []
    for relative in filter(None, listed):
        # The source-coverage inventory must name deleted paths and retired wire
        # identifiers exactly. It is historical review evidence, not an active
        # namespace declaration; all ordinary documents and source remain scanned.
        if relative == SOURCE_FEATURE_MANIFEST:
            continue
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
    missing = catalogue_missing()
    current = current_namespace_offenders()
    tiers = current_tier_offenders()
    residue = residue_offenders()

    if catalogue:
        print(f"[NAMESPACE CLOSURE] FAIL: {len(catalogue)} object(s) outside the legacy nineteen:")
        for name in catalogue:
            print(f"  the catalogue carries {name}")
    if missing:
        print("[NAMESPACE CLOSURE] FAIL: legacy domain objects without obligations: " + ", ".join(missing))
    for offender in current + tiers:
        print("[NAMESPACE CLOSURE] FAIL: " + offender)
    if residue:
        print(f"[NAMESPACE CLOSURE] FAIL: {len(residue)} VSTD- prefix(es) that should be bare:")
        for relative, number, token in residue:
            print(f"  {relative}:{number}: {token}")
    if catalogue or missing or current or tiers or residue:
        print(
            "\nThe current VSTD-NAMESPACE contains "
            + ", ".join(sorted(OBJECTS))
            + ".\nThe 19-object legacy domain catalogue retains old profile meanings."
            "\nThe VSTD- prefix survives historical profile references and the"
            " VSTD-NAMESPACE title, not current object identifiers."
        )
        return 1

    print(
        f"[NAMESPACE CLOSURE] PASS: {len(OBJECTS)} object kinds and eight meta-tiers "
        "match the current runtime; structural admission only; "
        "objective certification NOT_ESTABLISHED. The 19-object legacy domain "
        "catalogue and historical VSTD-1..VSTD-6 spellings retain their old meanings."
    )
    for name, definition in COMPOSITIONS.items():
        print(f"[NAMESPACE CLOSURE] COMPOSITION: {name} -- {definition}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
