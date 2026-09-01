"""Terminology: JavaScript Object Notation (JSON); Verifier Standard (VSTD); YAML Ain't Markup Language (YAML).

Side-effect-free generic-run manifest loading and execution-plan description.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from verifier.core.run_support import RunError


def load_manifest(manifest_path: Path) -> dict[str, Any]:
    text = manifest_path.read_text(encoding="utf-8")
    if manifest_path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RunError(
                "YAML manifest support is optional; install verifier-standard[yaml] or use JSON"
            ) from exc
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise RunError(f"Manifest at {manifest_path} must decode to a JSON/YAML object.")
    return data


def _validated_command(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    command = manifest.get("command")
    if not isinstance(command, list) or not command or not all(isinstance(c, str) for c in command):
        raise RunError(
            "manifest 'command' must be a non-empty list of strings (argv form). "
            "String/shell commands are rejected to close off shell-indirection attacks."
        )
    return tuple(command)


def describe_run_plan(manifest: Mapping[str, Any], manifest_dir: Path) -> dict[str, Any]:
    """Return the observable execution and capture paths without executing them.

    This is a review aid, not a sandbox analysis. A subprocess may access resources
    that are not named in a manifest, so the result deliberately says that the
    command's effective access remains outside VSTD's observation boundary.
    """

    command = _validated_command(manifest)
    root = manifest_dir.resolve()

    def path_record(path_value: Any) -> dict[str, Any]:
        declared = str(path_value)
        resolved = (root / declared).resolve()
        try:
            resolved.relative_to(root)
            outside = False
        except ValueError:
            outside = True
        return {
            "declared": declared,
            "resolved": str(resolved),
            "outside_manifest_directory": outside,
        }

    def artifacts(key: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for entry in manifest.get(key, []):
            if not isinstance(entry, Mapping) or "path" not in entry:
                raise RunError(f"manifest '{key}' entries must be objects with a path")
            record = path_record(entry["path"])
            record["role"] = str(entry.get("role", key[:-1]))
            record["present_before_execution"] = Path(record["resolved"]).is_file()
            result.append(record)
        return result

    return {
        "executes_without_sandbox": True,
        "manifest_directory": str(root),
        "command": list(command),
        "cwd": path_record(manifest.get("cwd", ".")),
        "repo_dir": path_record(manifest.get("repo_dir", ".")),
        "inputs": artifacts("inputs"),
        "outputs": artifacts("outputs"),
        "observation_limit": (
            "Declared paths describe receipt capture only; they do not confine the "
            "subprocess or enumerate everything it may access."
        ),
    }
