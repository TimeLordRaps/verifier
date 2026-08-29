"""Fail closed unless the named TIME file has exactly ``Status: CLEAR``."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]


def require_clear(path: Path) -> None:
    lines = [
        line for line in path.read_text(encoding="utf-8").splitlines()
        if line.startswith("Status:")
    ]
    if lines != ["Status: CLEAR"]:
        raise ValueError(
            f"release requires exactly one Status: CLEAR line; observed {lines or ['MISSING']}"
        )


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    path = Path(args[0]) if args else ROOT / "TIME.md"
    try:
        require_clear(path)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"[TIME BLOCKED] {exc}", file=sys.stderr)
        return 1
    print("[TIME CLEAR] release invariant satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
