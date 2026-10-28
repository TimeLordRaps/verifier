"""Measure replace and codec dispatch for Verifier Standard (VSTD) Tier zero.

The probe uses only the Python standard library and writes one JavaScript Object Notation
(JSON) receipt. It establishes behavior only for the selected interpreter process.

usage: python -B replace_codec_probe.py OUT.json
"""

from __future__ import annotations

import codecs
import copy
import dataclasses
import json
import os
from pathlib import Path
import sys
from typing import Any


EVENTS: list[str] = []
MUTANT = os.environ.get("VSTD_REPLACE_CODEC_MUTANT", "")


def _codec(name: str) -> codecs.CodecInfo:
    def encode(value: str, errors: str = "strict") -> tuple[bytes, int]:
        EVENTS.append("codec-encode")
        return b"PROBE", len(value)

    def decode(value: bytes, errors: str = "strict") -> tuple[str, int]:
        EVENTS.append("codec-decode")
        return "PROBE", len(value)

    return codecs.CodecInfo(name=name, encode=encode, decode=decode)


def run() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []

    def claim(identifier: str, holds: bool, observed: object) -> None:
        if MUTANT == identifier:
            holds = not holds
        rows.append({"id": identifier, "holds": bool(holds), "observed": observed})

    @dataclasses.dataclass
    class AttributeRecord:
        first: int = 1
        second: int = 2

        def __getattribute__(self, name: str) -> object:
            if name in {"first", "second"}:
                EVENTS.append("getattribute:" + name)
            return object.__getattribute__(self, name)

    EVENTS.clear()
    dataclasses.replace(AttributeRecord())
    claim(
        "replace-reads-omitted-fields",
        EVENTS == ["getattribute:first", "getattribute:second"],
        list(EVENTS),
    )

    @dataclasses.dataclass
    class Constructed:
        value: int = 1

        def __post_init__(self) -> None:
            EVENTS.append("post-init")

        def __replace__(self, **changes: object) -> "Constructed":
            EVENTS.append("dunder-replace")
            return type(self)(**changes)

    class Child(Constructed):
        pass

    original = Child(3)
    EVENTS.clear()
    rebuilt = dataclasses.replace(original)
    claim(
        "dataclasses-replace-reconstructs-runtime-class",
        type(rebuilt) is Child and EVENTS == ["post-init"],
        {"type": type(rebuilt).__name__, "events": list(EVENTS)},
    )
    claim(
        "dataclasses-replace-ignores-dunder-replace",
        "dunder-replace" not in EVENTS,
        list(EVENTS),
    )

    if hasattr(copy, "replace"):
        EVENTS.clear()
        copy.replace(original, value=4)
        claim(
            "copy-replace-dispatches-dunder-replace",
            EVENTS[:1] == ["dunder-replace"],
            list(EVENTS),
        )

    search_calls: list[str] = []
    codec_name = "vstd_probe_runtime_codec"

    def search(name: str) -> codecs.CodecInfo | None:
        search_calls.append(name)
        return _codec(codec_name) if name == codec_name else None

    codecs.register(search)
    try:
        EVENTS.clear()
        first = "x".encode(codec_name)
        second = b"x".decode(codec_name)
        claim(
            "unknown-codec-name-reaches-registered-search-and-codec",
            first == b"PROBE" and second == "PROBE"
            and EVENTS == ["codec-encode", "codec-decode"],
            {"search_calls": list(search_calls), "events": list(EVENTS)},
        )
        claim(
            "successful-codec-lookup-is-cached",
            search_calls.count(codec_name) == 1,
            list(search_calls),
        )

        before = len(search_calls)
        "x".encode("utf-8")
        claim(
            "known-stdlib-codec-wins-before-later-search-function",
            len(search_calls) == before,
            list(search_calls),
        )
    finally:
        codecs.unregister(search)

    try:
        codecs.lookup(codec_name)
    except LookupError:
        unavailable = True
    else:
        unavailable = False
    claim("codec-unregister-clears-selected-lookup", unavailable, unavailable)

    error_name = "vstd_probe_error_handler"

    def error_handler(error: UnicodeEncodeError) -> tuple[str, int]:
        EVENTS.append("error-handler")
        return "?", error.end

    codecs.register_error(error_name, error_handler)
    EVENTS.clear()
    encoded = "\N{LATIN SMALL LETTER E WITH ACUTE}".encode("ascii", error_name)
    claim(
        "registered-error-handler-runs-on-reachable-encoding-error",
        encoded == b"?" and EVENTS == ["error-handler"],
        {"encoded": encoded.hex(), "events": list(EVENTS)},
    )

    failed = [row["id"] for row in rows if not row["holds"]]
    return {
        "schema_version": "verifier-tier-zero-replace-codec-probe-1",
        "status": "PASS" if not failed else "FAIL",
        "python": sys.version.split()[0],
        "implementation": sys.implementation.name,
        "platform": sys.platform,
        "mutant": MUTANT or None,
        "results": rows,
        "failed": failed,
        "claim_boundary": (
            "PASS establishes only these selected-interpreter runtime observations. It does not "
            "close project call sites without exact-class, hook, registry, and error-handler facts."
        ),
    }


def main() -> int:
    output = Path(sys.argv[1])
    report = run()
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        "REPLACE CODEC PROBE " + report["status"]
        + f" {len(report['results']) - len(report['failed'])} of {len(report['results'])}",
        flush=True,
    )
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["run"]
