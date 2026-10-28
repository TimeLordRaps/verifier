"""Isolated fresh-SIM source loader with no ambient-package fallback.

Simulation (SIM) source is supplied only by the installed parent mechanism,
never by a public request. Exact bytes are materialized in a private temporary
import root, rechecked after import, and removed on exit. This loader is not a
hostile-host sandbox.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.abc
import json
from pathlib import Path
import sys
import tempfile
from typing import Any


def main() -> None:
    raw = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("fresh execution input exceeds bound")
    value = json.loads(raw)
    sources = value["sources"]
    manifest = value["source_manifest"]
    if set(sources) != set(manifest):
        raise ValueError("source closure differs")
    class Guard(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
            if fullname == "verifier" or fullname.startswith("verifier."):
                if fullname not in sources:
                    raise ImportError("source outside selected closure: " + fullname)
            return None

    with tempfile.TemporaryDirectory(prefix="vstd-fresh-sim-") as directory:
        root = Path(directory).resolve()
        for name, encoded in sources.items():
            source = base64.b64decode(encoded, validate=True)
            if "sha256:" + hashlib.sha256(source).hexdigest() != manifest[name]["sha256"]:
                raise ValueError("selected source differs")
            parts = name.split(".")
            target_path = (root.joinpath(*parts, "__init__.py")
                           if manifest[name]["package"]
                           else root.joinpath(*parts).with_suffix(".py"))
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_bytes(source)

        sys.meta_path.insert(0, Guard())
        sys.path.insert(0, str(root))
        import verifier
        from verifier import core
        from verifier.core import certificate, signature_keys
        from verifier import domains
        from verifier.domains import common, sim
        from verifier.domains import contracts
        from verifier.domains.contracts import sim_fresh_worker

        modules = (
            verifier, core, certificate, signature_keys, domains, common, sim,
            contracts, sim_fresh_worker,
        )
        loaded = {}
        for module in modules:
            name = module.__name__
            source_path = Path(module.__file__).resolve()
            if not source_path.is_relative_to(root):
                raise ValueError("loaded source escaped selected closure")
            source = source_path.read_bytes()
            if "sha256:" + hashlib.sha256(source).hexdigest() != manifest[name]["sha256"]:
                raise ValueError("loaded source differs")
            loaded[name] = manifest[name]
        capture = sim_fresh_worker.measure(value["workload"], {
            "challenge": value["challenge"], "source_manifest": manifest})
    result = {
        "challenge": value["challenge"],
        "workload_digest": "sha256:" + hashlib.sha256(
            json.dumps(value["workload"], sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False).encode()).hexdigest(),
        "source_manifest": manifest,
        "loaded_source_manifest": loaded,
        "capture": capture,
    }
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise SystemExit(2)
    except (OSError, ImportError, MemoryError):
        raise SystemExit(3)
