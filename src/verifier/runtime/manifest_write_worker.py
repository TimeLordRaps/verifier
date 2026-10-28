"""Fixed private manifest publication experiments for Verifier Standard (VSTD).

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Only installed handlers and fixed fixtures execute. Filesystem faults occur in
this worker only. No caller command, subject module or operator file is accepted.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any


def source_pins() -> dict[str, str]:
    # Keep bootstrap pinning standard-library-only: importing a package helper
    # before setting a fresh bytecode prefix could load stale cached code.
    root = Path(__file__).resolve().parents[1]
    paths = [path for path in root.rglob("*.py") if "__pycache__" not in path.parts]
    paths.extend(root / name for name in ("standard/POLISH_INVOCATION_LEDGER.md", "standard/PACKAGE_POLISH.md"))
    return {path.relative_to(root).as_posix(): "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(paths)}


def observe(directory: Path) -> dict[str, Any]:
    import argparse
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import redirect_stdout
    import io
    import subprocess
    import threading
    from verifier.runtime import namespace_admission, namespace_cli

    original = '{ "policy": {"epoch":1}, "labels":["OBJECT","LEDGER"], "evidence":"unverified" }'
    subject = 'raise RuntimeError("subject must not execute")\ndef calculate(): pass\n'

    def text(path: Path) -> str:
        # Decode exact bytes without text-mode newline normalization. Otherwise
        # an altered publication or source can falsely compare equal on replay.
        return path.read_bytes().decode("utf-8")

    def repository(name: str) -> Path:
        root = directory / name
        root.mkdir()
        subprocess.run(["git", "init", "-q", str(root)], capture_output=True, check=True, timeout=10)
        (root / "subject.py").write_bytes(subject.encode("utf-8"))
        return root

    def template(root: Path, *, preview: bool = False) -> int:
        return namespace_cli.handle_template(argparse.Namespace(source_root=str(root), json=preview, namespace_extension=[]))

    def formatter(path: Path, *, write: bool = True) -> int:
        return namespace_cli.handle_format(argparse.Namespace(manifest=str(path), write=write))

    def call(action: Any, *, capture: bool = True) -> dict[str, Any]:
        output = io.StringIO()
        try:
            if capture:
                with redirect_stdout(output):
                    code = action()
            else:
                code = action()
            return {"exit": code, "exception": None, "stdout": output.getvalue()}
        except (ValueError, OSError) as exc:
            return {"exit": None, "exception": type(exc).__name__, "stdout": output.getvalue()}

    def temporary_files(root: Path) -> list[str]:
        return sorted(path.name for path in root.glob(".vstd-format-*"))

    root = repository("template")
    target = root / "objects.vstd"
    before_exists = target.exists()
    preview = call(lambda: template(root, preview=True))
    draft = json.loads(preview["stdout"])
    preview["stdout"] = ""  # The parsed draft is retained once.
    after_preview_exists = target.exists()
    original_open = Path.open
    template_attempts: list[int] = []

    def count_template_attempt(path: Path, *args: Any, **kwargs: Any) -> Any:
        mode = args[0] if args else kwargs.get("mode", "r")
        if path == target and mode == "xb":
            template_attempts.append(1)
        return original_open(path, *args, **kwargs)

    try:
        Path.open = count_template_attempt
        before_first = len(template_attempts)
        first = call(lambda: template(root))
        first_attempts = len(template_attempts) - before_first
        published = text(target)
        before_retry = len(template_attempts)
        retry = call(lambda: template(root))
        retry_attempts = len(template_attempts) - before_retry
    finally:
        Path.open = original_open
    created = {"before_exists": before_exists, "preview": preview, "draft": draft,
        "after_preview_exists": after_preview_exists, "first": first, "published": published,
        "retry": retry, "after_retry": text(target), "attempt_limit": 1,
        "publication_attempts": {"first": first_attempts, "retry": retry_attempts},
        "source_before": subject, "source_after": text(root / "subject.py")}

    root = directory / "format"
    root.mkdir()
    target = root / "objects.vstd"
    target.write_text(original, encoding="utf-8")
    sentinel = root / "unrelated.txt"
    sentinel.write_text("unrelated", encoding="utf-8")
    preview = call(lambda: formatter(target, write=False))
    after_preview = text(target)
    original_replace = namespace_cli.os.replace
    format_attempts: list[int] = []

    def count_format_attempt(source: Any, destination: Any) -> None:
        format_attempts.append(1)
        original_replace(source, destination)

    try:
        namespace_cli.os.replace = count_format_attempt
        before_first = len(format_attempts)
        first = call(lambda: formatter(target))
        first_attempts = len(format_attempts) - before_first
        after_first = text(target)
        before_second = len(format_attempts)
        second = call(lambda: formatter(target))
        second_attempts = len(format_attempts) - before_second
    finally:
        namespace_cli.os.replace = original_replace
    formatted = {"before": original, "preview": preview, "after_preview": after_preview,
        "first": first, "after_first": after_first, "second": second,
        "after_second": text(target), "temporary_files": temporary_files(root),
        "attempt_limit": 1,
        "publication_attempts": {"first": first_attempts, "second": second_attempts},
        "sentinel": text(sentinel)}

    invalid = []
    for malformed in ('{"label":"OBJECT","label":"LEDGER"}', '{"amount":0.1}', '[]'):
        target.write_text(malformed, encoding="utf-8")
        outcome = call(lambda: formatter(target))
        invalid.append({"before": malformed, "outcome": outcome,
            "after": text(target), "temporary_files": temporary_files(root)})

    # Replace faults can happen before or after the actual publication boundary.
    # An early competing write is injected after staging, before the source check.
    publications = {}
    replace, named_temporary = namespace_cli.os.replace, namespace_cli.tempfile.NamedTemporaryFile
    for phase in ("before", "after", "race"):
        target.write_text(original, encoding="utf-8")
        calls = []

        def replacing(source: Any, destination: Any) -> None:
            calls.append(1)
            if phase == "after":
                replace(source, destination)
            raise OSError("injected publication failure")

        class ConcurrentEdit:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                self.stream = named_temporary(*args, **kwargs)

            def __enter__(self) -> Any:
                return self.stream.__enter__()

            def __exit__(self, *args: Any) -> Any:
                result = self.stream.__exit__(*args)
                target.write_bytes(b'{"concurrent":"preserve"}\n')
                return result

        try:
            namespace_cli.os.replace = replacing
            if phase == "race":
                namespace_cli.tempfile.NamedTemporaryFile = ConcurrentEdit
            outcome = call(lambda: formatter(target))
        finally:
            namespace_cli.os.replace = replace
            namespace_cli.tempfile.NamedTemporaryFile = named_temporary
        publications[phase] = {"before": original, "outcome": outcome,
            "after": text(target), "temporary_files": temporary_files(root),
            "replace_calls": len(calls), "sentinel": text(sentinel)}

    root = repository("partial")
    target = root / "objects.vstd"
    partial_draft = json.loads(call(lambda: template(root, preview=True))["stdout"])
    before_exists = target.exists()
    original_open = Path.open
    writes = []

    class PartialWrite:
        def __init__(self, stream: Any) -> None:
            self.stream = stream

        def __enter__(self) -> PartialWrite:
            self.stream.__enter__()
            return self

        def __exit__(self, *args: Any) -> Any:
            return self.stream.__exit__(*args)

        def write(self, raw: bytes) -> int:
            writes.append(1)
            self.stream.write(raw[:8])
            self.stream.flush()
            raise OSError("injected partial create")

    def opening(path: Path, *args: Any, **kwargs: Any) -> Any:
        stream = original_open(path, *args, **kwargs)
        return PartialWrite(stream) if path == target and args == ("xb",) else stream

    try:
        Path.open = opening
        outcome = call(lambda: template(root))
    finally:
        Path.open = original_open
    partial = text(target)
    retry = call(lambda: template(root))
    interrupted = {"draft": partial_draft, "before_exists": before_exists, "outcome": outcome,
        "partial": partial, "writes": len(writes), "retry": retry,
        "after_retry": text(target), "source_before": subject,
        "source_after": text(root / "subject.py")}

    root = repository("concurrent")
    target = root / "objects.vstd"
    concurrent_draft = json.loads(call(lambda: template(root, preview=True))["stdout"])
    before_exists = target.exists()
    build, barrier, discoveries = namespace_admission.build_template, threading.Barrier(2), []

    def synchronized(*args: Any, **kwargs: Any) -> dict[str, Any]:
        result = build(*args, **kwargs)
        discoveries.append(1)
        barrier.wait(timeout=10)
        return result

    concurrent_open = Path.open
    concurrent_attempts: dict[int, int] = {}
    attempt_lock = threading.Lock()

    def count_concurrent_attempt(path: Path, *args: Any, **kwargs: Any) -> Any:
        mode = args[0] if args else kwargs.get("mode", "r")
        if path == target and mode == "xb":
            with attempt_lock:
                thread = threading.get_ident()
                concurrent_attempts[thread] = concurrent_attempts.get(thread, 0) + 1
        return concurrent_open(path, *args, **kwargs)

    try:
        namespace_admission.build_template = synchronized
        Path.open = count_concurrent_attempt
        # One shared redirection outside the threads avoids competing global
        # stdout contexts. Only the final observation document leaves this worker.
        with redirect_stdout(io.StringIO()), ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: call(lambda: template(root), capture=False), range(2)))
    finally:
        namespace_admission.build_template = build
        Path.open = concurrent_open
    concurrent = {"before_exists": before_exists, "draft": concurrent_draft, "discoveries": len(discoveries),
        "outcomes": outcomes, "published": text(target), "attempt_limit": 1,
        "publication_attempts": sorted(concurrent_attempts.values()),
        "source_before": subject, "source_after": text(root / "subject.py")}
    return {"template": created, "format": formatted, "invalid": invalid,
            "publication": publications, "partial": interrupted, "concurrent": concurrent}


def main() -> int:
    raw = sys.stdin.buffer.read(16385)
    if len(raw) > 16384:
        raise ValueError("worker request exceeds bound")
    request = json.loads(raw)
    if type(request) is not dict or set(request) != {"schema_version", "nonce", "object_id", "object_digest", "collection_digest"}:
        raise ValueError("closed worker request required")
    if request["schema_version"] != "verifier-manifest-publication-request-1":
        raise ValueError("worker request version differs")
    if any(type(value) is not str or not 1 <= len(value) <= 256 for value in request.values()):
        raise ValueError("bounded worker bindings required")
    before = source_pins()
    with tempfile.TemporaryDirectory(prefix="vstd-manifest-check-") as temporary:
        directory = Path(temporary).resolve(strict=True)
        sys.pycache_prefix = str(directory / "empty-bytecode")
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        previous = Path.cwd()
        try:
            # Git is fixture infrastructure, not a subject-supplied executable.
            # A private working directory avoids repository-local tool shadowing;
            # user/system Git configuration must not install hooks or helpers.
            os.chdir(directory)
            os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
            os.environ["GIT_CONFIG_GLOBAL"] = os.devnull
            observations = observe(directory)
        finally:
            os.chdir(previous)  # Release the directory before Windows cleanup.
    if before != source_pins():
        raise ValueError("worker source changed")
    sys.stdout.write(json.dumps({"schema_version": "verifier-manifest-publication-observations-1",
        "request": request, "source_pins": before, "observations": observations},
        sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
