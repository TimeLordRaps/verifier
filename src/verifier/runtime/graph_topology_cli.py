"""Bounded graph-topology command for Verifier Standard (VSTD).

JavaScript Object Notation (JSON) input is strictly decoded before interpretation.
This command inspects a graph projection; it does not validate the enclosing
receipt, inspect payload bytes, establish causality, or issue conformance.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
from typing import Any

from verifier.core.receipt import strict_json_loads
from verifier.data.models import ProvenanceHypergraph


MAX_DOCUMENT_BYTES = 2 * 1024 * 1024


def _read_document(path: Path) -> dict[str, Any]:
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("topology input must be an ordinary file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("topology input must remain an ordinary file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_DOCUMENT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise ValueError("topology input exceeds the 2 MiB document limit")
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except RecursionError as exc:
        raise ValueError("topology input exceeds the parser nesting limit") from exc
    if not isinstance(value, dict):
        raise ValueError("topology input must be a JSON object")
    return value


def handle_graph_topology_command(args: argparse.Namespace) -> int:
    """Emit bounded diagnostics; 1 means conflict/invalidity, 2 unresolved facets."""

    from verifier.interoperability.graph_topology import (
        GraphTopologyContract,
        analyze_graph_topology,
    )

    path = Path(args.receipt)
    payload = _read_document(path / "receipt.json" if path.is_dir() else path)
    if payload.get("schema_version") != "VSTD-DATA-0.1" or not isinstance(
        payload.get("hypergraph"), dict
    ):
        raise ValueError("topology requires a VSTD-DATA-0.1 graph inspection envelope")
    try:
        graph = ProvenanceHypergraph.from_dict(payload["hypergraph"])
    except (TypeError, AttributeError, RecursionError) as exc:
        raise ValueError("malformed graph inspection envelope") from exc
    contract = GraphTopologyContract.from_dict(_read_document(Path(args.contract)))
    report = analyze_graph_topology(graph, contract, max_assignments=args.max_assignments).to_dict()
    report["input_boundary"] = (
        "Exact canonical graph projection and supplied interpretation only; enclosing "
        "receipt validity, payload integrity, physical causation and conformance are not established."
    )
    if not args.json:
        print("[EXPERIMENTAL TOPOLOGY DIAGNOSTIC; NO CONFORMANCE]")
    print(json.dumps(report, indent=2, sort_keys=True))
    statuses = {
        report[facet]["status"]
        for facet in ("structural", "boolean_consistency", "temporal_consistency")
    }
    if statuses & {"INVALID", "CONFLICTED"}:
        return 1
    return 0 if statuses == {"CONSISTENT"} else 2
