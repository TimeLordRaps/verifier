#!/usr/bin/env python3
"""Demonstrate that GitHub success and merge state grant no VSTD verdict."""

from __future__ import annotations

import json
from pathlib import Path

from verifier.experimental_workflow import github_snapshot_to_events, load_manifest


HERE = Path(__file__).resolve().parent


def main() -> int:
    snapshot = json.loads((HERE / "github_snapshot.json").read_text(encoding="utf-8"))
    expected = load_manifest(HERE / "manifest.json")
    events = github_snapshot_to_events(snapshot)
    if list(events) != expected["workflow_events"]:
        raise SystemExit("generated GitHub events do not match the bound manifest")
    if any(event["verification_effect"] != "NONE" for event in events):
        raise SystemExit("a platform event was incorrectly upgraded")
    summary = {
        "events": len(events),
        "native_states": sorted({event["native_state"] for event in events}),
        "vstd_verdicts_granted": 0,
        "manifest_digest": expected["manifest_digest"],
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
