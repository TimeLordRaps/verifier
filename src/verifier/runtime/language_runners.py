"""Language-neutral Verifier Standard (VSTD) runner selection and process capture.

JavaScript Object Notation (JSON) is the extension wire format. Python hosts
the orchestration, not the standard's object semantics. Detection is heuristic.
The built-in trusted-local process runner is NOT a security sandbox. Object
isolation profiles require an explicitly selected optional backend; a profile
name or installed extension never establishes isolation or corrigibility.
The selected entry is observed before any adapter or backend hook runs, again before
launch, and after the process: any drift is UNKNOWN, and the original receipt is never
rewritten. The Python interpreter and adapter-named executables resolve on the host
outside the subject root and are bound by file identity where the
platform exposes it; exec identity itself stays UNKNOWN. For an explicitly selected non-Python
extension, the reserved worker exit codes 124 to 127 are UNKNOWN blockers read from the integer exit
code alone; subject output never selects or adds a blocker, and other nonzero exits stay FAIL. A
non-None exit status whose exact type is not ``int`` is an invalid process observation, never PASS.
"""
from __future__ import annotations

import argparse
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
from importlib.util import find_spec
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


PROTOCOL = "verifier-language-runner-1"
EXTENSION_GROUP = "verifier.language_runners"
SANDBOX_GROUP = "verifier.sandbox_backends"
_AVAILABLE = frozenset({
    "ada", "assembly", "c", "cobol", "cpp", "csharp", "fortran", "go", "java",
    "javascript", "julia", "lisp", "matlab", "object-pascal", "objective-c", "perl",
    "php", "prolog", "r", "rust", "sas", "scratch", "sql", "swift", "visual-basic",
})
# October 2026 TIOBE positions 2-25, not a claim of implemented toolchains.
_TARGETS = (
    ("c", (".c", ".h")), ("cpp", (".cc", ".cpp", ".cxx", ".h", ".hpp")),
    ("java", (".java",)), ("csharp", (".cs",)), ("javascript", (".js", ".mjs", ".cjs", ".jsx")),
    ("visual-basic", (".vb",)), ("r", (".r",)), ("sql", (".sql",)),
    ("rust", (".rs",)), ("go", (".go",)), ("php", (".php",)),
    ("fortran", (".f", ".f90", ".f95", ".f03", ".f08")), ("swift", (".swift",)),
    ("scratch", (".sb2", ".sb3")), ("cobol", (".cob", ".cbl")), ("perl", (".pl", ".pm")),
    ("julia", (".jl",)), ("object-pascal", (".pas", ".dpr")), ("matlab", (".m",)),
    ("ada", (".adb", ".ads")), ("sas", (".sas",)), ("assembly", (".s", ".asm")),
    ("classic-visual-basic", (".bas", ".frm", ".cls")), ("objective-c", (".m", ".mm", ".h")),
)
_SUPPLEMENTS = (("lisp", (".lisp", ".lsp", ".cl", ".scm")),
               ("typescript", (".ts", ".tsx", ".mts", ".cts")), ("prolog", (".pl", ".pro")))
_SUFFIXES = dict((("python", (".py", ".pyw")), *_TARGETS, *_SUPPLEMENTS))
_EXCLUDED = frozenset({".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist", "target"})
_PROFILE_NAMES = {"OBJECT": "process-basic", "MODEL": "model-corrigibility",
                  "AGENT": "agent-open-ended", "BOT": "bot-isolated", "SIM": "sim-contained"}
# Closed blocker vocabulary: the RUNNER_* codes a report carries verbatim. The one exception is the
# RUNNER_TOOLCHAIN_MISSING:<tool> prefix, whose tool token _resource_blocker validates before passing it on.
# Exception text outside this set is replaced by a fixed code. tests/test_runner_extensions.py checks that
# every RUNNER_* literal in this module and in extensions/ is listed here, excepting that prefix.
_BLOCKER_CODES = frozenset({
    "RUNNER_ARGUMENT_VECTOR_INVALID", "RUNNER_BOT_EXACT_BINDINGS_REQUIRED",
    "RUNNER_CONTRACT_REJECTED", "RUNNER_DIALECT_UNSUPPORTED", "RUNNER_DISCOVERY_SCOPE_INVALID",
    "RUNNER_ADAPTER_TERMINATED", "RUNNER_ENTRY_MISSING", "RUNNER_ENTRY_OUTSIDE_ROOT", "RUNNER_EXCEPTION_UNCLASSIFIED",
    "RUNNER_EXTENSION_EXIT_OUTPUT_CAPACITY", "RUNNER_EXTENSION_EXIT_RESOURCE_UNAVAILABLE",
    "RUNNER_EXTENSION_EXIT_TIMEOUT", "RUNNER_EXTENSION_EXIT_TOOLCHAIN_UNAVAILABLE",
    "RUNNER_EXTENSION_NOT_INSTALLED", "RUNNER_EXTENSION_PACKAGE_UNSUPPORTED",
    "RUNNER_EXTENSION_PROTOCOL_DIFFERS", "RUNNER_EXTENSION_SELECTION_AMBIGUOUS",
    "RUNNER_ISOLATION_BACKEND_NOT_QUALIFIED", "RUNNER_LANGUAGE_SELECTION_DIFFERS",
    "RUNNER_OBJECT_KIND_UNSUPPORTED", "RUNNER_OPENSHELL_CLI_MISSING",
    "RUNNER_OPENSHELL_COMMAND_INCOMPLETE", "RUNNER_OPENSHELL_EXECUTION_INCOMPLETE",
    "RUNNER_OPENSHELL_GATEWAY_NOT_REGISTERED", "RUNNER_OPENSHELL_GATEWAY_VERSION_OR_HEALTH_DIFFERS",
    "RUNNER_OPENSHELL_UNAVAILABLE_OR_INVALID_RESPONSE", "RUNNER_OPENSHELL_VERSION_DIFFERS",
    "RUNNER_PROCESS_OBSERVATION_INVALID", "RUNNER_PROCESS_OBSERVATION_MISSING",
    "RUNNER_RESOURCE_UNAVAILABLE", "RUNNER_SANDBOX_BINDING_CHANGED",
    "RUNNER_SANDBOX_CLEANUP_NOT_ESTABLISHED", "RUNNER_SANDBOX_CLEANUP_OWNERSHIP_DIFFERS",
    "RUNNER_SANDBOX_CONFIG_CAPACITY", "RUNNER_SANDBOX_CONFIG_FIELDS", "RUNNER_SANDBOX_CONFIG_REQUIRED",
    "RUNNER_SANDBOX_CONFIG_VERSION", "RUNNER_SANDBOX_CONTINUITY_NOT_IMPLEMENTED",
    "RUNNER_SANDBOX_DELETE_NOT_ESTABLISHED", "RUNNER_SANDBOX_DUPLICATE_KEY",
    "RUNNER_SANDBOX_EFFECTIVE_POLICY_DIFFERS", "RUNNER_SANDBOX_EXTENSION_AMBIGUOUS",
    "RUNNER_SANDBOX_EXTENSION_NOT_INSTALLED", "RUNNER_SANDBOX_IDENTITY_OR_READINESS_DIFFERS",
    "RUNNER_SANDBOX_IMAGE_MUST_BE_DIGEST_PINNED", "RUNNER_SANDBOX_INPUT_CAPACITY",
    "RUNNER_SANDBOX_INPUT_OUTSIDE_ROOT", "RUNNER_SANDBOX_INPUT_PATH_INVALID", "RUNNER_SANDBOX_INPUT_SYMLINK",
    "RUNNER_SANDBOX_LIFECYCLE_UNSUPPORTED", "RUNNER_SANDBOX_NEGATIVE_CONTROLS_NOT_ESTABLISHED",
    "RUNNER_SANDBOX_NEGATIVE_CONTROL_FAILED", "RUNNER_SANDBOX_POLICY_ADMISSION_NOT_ESTABLISHED",
    "RUNNER_SANDBOX_PROTOCOL_DIFFERS", "RUNNER_SANDBOX_REQUEST_VERSION",
    "RUNNER_SANDBOX_RESOURCE_BOUND_INVALID", "RUNNER_SANDBOX_SCOPE_REASON_REQUIRED",
    "RUNNER_SANDBOX_SOURCE_BINDING_DIFFERS", "RUNNER_SANDBOX_SOURCE_CHANGED",
    "RUNNER_SANDBOX_STAGING_UNAVAILABLE", "RUNNER_SANDBOX_STOP_NOT_ESTABLISHED",
    "RUNNER_SANDBOX_TARGET_INVALID", "RUNNER_SANDBOX_UNEXPECTED_NETWORK_GRANT",
    "RUNNER_SUBJECT_OR_REMOTE_EXECUTION_FAILED", "RUNNER_SUBJECT_SOURCE_CHANGED", "RUNNER_TIMEOUT_INVALID",
    "RUNNER_TOOL_IDENTITY_CHANGED", "RUNNER_TOOL_IDENTITY_UNKNOWN", "RUNNER_TOOL_PATH_NOT_TRUSTED",
    "RUNNER_TOOLCHAIN_VERSION_UNKNOWN", "RUNNER_TRUSTED_LOCAL_SELECTION_REQUIRED",
    # Raised by the optional language adapter (vstd-language-runners); listed so they are not generic.
    "RUNNER_ARGUMENT_INVALID", "RUNNER_ENTRY_INVALID", "RUNNER_ENVIRONMENT_UNSUPPORTED",
    "RUNNER_LANGUAGE_UNSUPPORTED", "RUNNER_RECEIPT_WRONG_VERSION", "RUNNER_ROOT_INVALID",
})
# Adapters report a missing toolchain as FileNotFoundError("RUNNER_TOOLCHAIN_MISSING:<tool>").
_TOOLCHAIN_PREFIX = "RUNNER_TOOLCHAIN_MISSING:"
_TOOL_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9+_-]{0,31}")
# Reserved exit codes of an explicitly selected non-Python extension worker, by that worker's contract. A
# subject or compiler can return the same integers naturally; the mapping then yields UNKNOWN, never PASS.
_EXTENSION_EXIT_BLOCKERS = {124: "RUNNER_EXTENSION_EXIT_TIMEOUT",
                           125: "RUNNER_EXTENSION_EXIT_OUTPUT_CAPACITY",
                           126: "RUNNER_EXTENSION_EXIT_RESOURCE_UNAVAILABLE",
                           127: "RUNNER_EXTENSION_EXIT_TOOLCHAIN_UNAVAILABLE"}


# Only these exact built-in types have their payload read on the failure path. A subclass can define
# args, __str__, __repr__, filename or __class__ as code that runs there (SystemExit included), so its
# payload is never inspected and it maps to a fixed code by type alone.
_PAYLOAD_TYPES = (FileNotFoundError, ValueError, KeyError, TypeError, AttributeError, RuntimeError)


def _single_message(exc: BaseException) -> str:
    """The exception's one plain-string argument, or empty; subclasses and other shapes are not read."""

    if type(exc) not in _PAYLOAD_TYPES:
        return ""
    args = exc.args
    return args[0] if type(args) is tuple and len(args) == 1 and type(args[0]) is str else ""


def _resource_blocker(exc: BaseException) -> str:
    """Only a validated tool token from a missing-toolchain FileNotFoundError is actionable."""

    message = _single_message(exc)
    if (type(exc) is FileNotFoundError and message.startswith(_TOOLCHAIN_PREFIX)
            and _TOOL_TOKEN.fullmatch(message[len(_TOOLCHAIN_PREFIX):])):
        return message
    return "RUNNER_RESOURCE_UNAVAILABLE"


def _contract_blocker(exc: BaseException) -> str:
    """Pass through only a listed code; arbitrary exception text never becomes a blocker."""

    message = _single_message(exc)
    return message if message in _BLOCKER_CODES else "RUNNER_CONTRACT_REJECTED"


_NO_CWD_EXE_SEARCH = "NoDefaultCurrentDirectoryInExePath"
_PATHEXT_DEFAULT = ".COM;.EXE;.BAT;.CMD"
_CHUNK = 1 << 20


_OPEN_EXECUTABLE = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
# Win32 CreateFileW constants. FILE_SHARE_READ alone refuses other writers, renames and deletes while held.
_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x80
# Detection visits at most this many directories unless the caller passes max_directories. The hard-link
# alias scan has its own bounds and reports UNKNOWN when either is exceeded.
_DIRECTORY_VISIT_BOUND = 20000
_ALIAS_DIRECTORY_BOUND = 20000
_ALIAS_ENTRY_BOUND = 200000


class _ToolIdentityUnknown(Exception):
    """An executable's identity could not be established before launch; the runner maps it to a closed blocker."""


def _classify(link: os.stat_result) -> str:
    """One lstat result as symlink, reparse point, directory, file or other. Links are never followed."""

    if stat.S_ISLNK(link.st_mode):
        return "symlink"
    if getattr(link, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        return "reparse"
    if stat.S_ISDIR(link.st_mode):
        return "directory"
    return "file" if stat.S_ISREG(link.st_mode) else "other"


def _identity(link: os.stat_result) -> tuple[int, int, int, int]:
    """Device, inode, size and mtime: the fields a path lstat and a handle fstat report identically.

    Windows reports change time differently from a path and from a handle, so it is not compared here.
    """

    return (link.st_dev, link.st_ino, link.st_size, link.st_mtime_ns)


def _walk(top: str, *, max_directories: int, exclude: frozenset[str]) -> Iterator[tuple[str, str, os.stat_result | None]]:
    """Scandir walk that neither follows links nor reparse points, and visits at most ``max_directories``.

    Yields ``(path, kind, lstat)`` for each non-directory entry. An entry whose lstat fails yields
    ``(path, "unobservable", None)`` and is never traversed. A directory named in ``exclude`` yields
    ``(path, "excluded", lstat)`` and is not traversed. A queued directory whose (device, inode) changed
    after discovery, or that cannot be listed, yields ``(path, "unobservable", None)`` and is not
    traversed, so a junction swapped in mid-walk is not followed and a listing error ends nothing.
    When the directories discovered (visited plus queued) would exceed ``max_directories``, the walk yields
    ``("", "bounded", None)`` and ends.
    """

    pending: list[tuple[str, tuple[int, int] | None]] = [(top, None)]
    visited = 0
    while pending:
        directory, expected = pending.pop()
        visited += 1
        try:
            here = os.lstat(directory)
        except OSError:
            yield directory, "unobservable", None
            continue
        if _classify(here) != "directory" or (expected is not None and (here.st_dev, here.st_ino) != expected):
            yield directory, "unobservable", None
            continue
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    path = os.path.join(directory, entry.name)
                    try:
                        link = os.lstat(path)
                    except OSError:
                        yield path, "unobservable", None
                        continue
                    kind = _classify(link)
                    if kind == "directory":
                        if entry.name in exclude:
                            yield path, "excluded", link
                            continue
                        # Bound the discovered set, not only the visited one, so a wide directory cannot queue without limit.
                        if visited + len(pending) + 1 > max_directories:
                            yield "", "bounded", None
                            return
                        pending.append((path, (link.st_dev, link.st_ino)))
                        continue
                    yield path, kind, link
        except OSError:
            yield directory, "unobservable", None


def _root_holds_identity(root: Path, device: int, inode: int) -> bool:
    """Whether any non-link entry under ``root``, excluded directories included, has this file identity.

    An incomplete scan (a bound reached, or an entry that cannot be observed) raises _ToolIdentityUnknown.
    """

    walk = _walk(str(root), max_directories=_ALIAS_DIRECTORY_BOUND, exclude=frozenset())
    entries = 0
    try:
        for _, kind, link in walk:
            if kind in ("bounded", "unobservable"):
                raise _ToolIdentityUnknown()
            if kind in ("symlink", "reparse") or link is None:
                continue
            entries += 1
            if entries > _ALIAS_ENTRY_BOUND:
                raise _ToolIdentityUnknown()
            if (link.st_dev, link.st_ino) == (device, inode):
                return True
    finally:
        walk.close()
    return False


def _path_search(name: str) -> str | None:
    """First regular file for a bare name in the absolute PATH directories, or None.

    Relative and empty PATH entries name the working directory, which is the subject root
    for a run, so they are skipped. On Windows the executable extensions are tried first.
    """

    suffixes = [""]
    if os.name == "nt" and not Path(name).suffix:
        extensions = [item.strip() for item in os.environ.get("PATHEXT", _PATHEXT_DEFAULT).split(";")]
        suffixes = [item for item in extensions if item] + [""]
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        directory = directory.strip().strip('"')
        if not directory or not os.path.isabs(directory):
            continue
        for suffix in suffixes:
            candidate = os.path.join(directory, name + suffix)
            if os.path.isfile(candidate):
                return candidate
    return None


def _held_digest(handle: int) -> str:
    """Secure Hash Algorithm 256-bit (SHA-256) of the bytes behind an open descriptor, read from the start."""

    digest = hashlib.sha256()
    os.lseek(handle, 0, os.SEEK_SET)
    for chunk in iter(lambda: os.read(handle, _CHUNK), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _open_held_executable(path: Path) -> int:
    """Open a selected executable so that writers, renames and deletes are refused while it is held.

    POSIX: a read-only descriptor. Its bytes are hashed through it, but nothing refuses a same-inode
    write; a changed write is caught by the digest comparison, not prevented.
    Windows: CreateFileW with FILE_SHARE_READ alone, wrapped as a C runtime descriptor so the module
    reads it with the same os calls. Closing the descriptor closes the handle.
    """

    if sys.platform != "win32":
        return os.open(path, _OPEN_EXECUTABLE)
    import ctypes
    from ctypes import wintypes
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                     wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.CreateFileW(str(path), _GENERIC_READ, _FILE_SHARE_READ, None, _OPEN_EXISTING,
                                  _FILE_ATTRIBUTE_NORMAL, None)
    if handle is None or handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except OSError:
        kernel32.CloseHandle(handle)
        raise


class _TrustedTool:
    """An adapter-named host executable bound for one launch: resolved path, file identity, content digest, handle.

    The handle stays open until the process ends. Its SHA-256 digest is taken before launch and re-read
    through the same handle before launch and after the run. On Windows the handle's share mode also refuses
    other writers, renames and deletes while it is held. The launch names the path, and the bytes the
    operating system executes are not read through this handle, so executed image bytes and atomic exec
    identity stay UNKNOWN, and the report says so.
    """

    def __init__(self, path: str, handle: int, identity: tuple[int, int, int, int], digest: str) -> None:
        self.path = path
        self._handle = handle
        self._identity = identity
        self._digest = digest

    def still_bound(self) -> str:
        """BOUND while the path names the bound identity and the held bytes hash to the bound digest.

        CHANGED on any difference, including a same-size rewrite with the modification time restored.
        UNKNOWN when the path or the held descriptor cannot be read; nothing is inferred from a failed read.
        """

        try:
            current = os.lstat(self.path)
        except FileNotFoundError:
            return "CHANGED"
        except OSError:
            return "UNKNOWN"
        if _classify(current) != "file" or _identity(current) != self._identity:
            return "CHANGED"
        try:
            digest = _held_digest(self._handle)
        except OSError:
            return "UNKNOWN"
        return "BOUND" if digest == self._digest else "CHANGED"

    def describe(self) -> dict[str, Any]:
        return {"scope": "host_outside_subject_root", "identity_checks": ["pre_launch", "post_run"],
                "content_digest": "SHA-256", "content_checks": ["pre_launch", "post_run"],
                "handle_held_during_run": True,
                "write_rename_delete_refusal": "SHARE_MODE_READ_ONLY" if sys.platform == "win32" else "NOT_ENFORCED",
                "executed_image_bytes": "UNKNOWN", "atomic_exec_identity": "UNKNOWN"}

    def close(self) -> None:
        os.close(self._handle)


def _trusted_executable(name: str, root: Path) -> _TrustedTool:
    """Resolve an adapter-named executable on the host and bind it by identity and content for one launch.

    Accepted: an absolute path, or a bare name found through an absolute PATH directory, that resolves
    outside ``root`` and has no hard-link alias of any file under ``root``. Refused (FAIL): a relative
    path, a resolution inside ``root``, or such an alias. Missing tools are toolchain blockers. Any
    failure to resolve, open, hash or establish identity raises _ToolIdentityUnknown and nothing is launched.
    """

    if Path(name).is_absolute():
        candidate = name
    elif re.search(r"[\\/:]", name):
        raise ValueError("RUNNER_TOOL_PATH_NOT_TRUSTED")
    else:
        found = _path_search(name)
        if found is None:
            raise FileNotFoundError(_TOOLCHAIN_PREFIX + name if _TOOL_TOKEN.fullmatch(name) else "no executable on PATH")
        candidate = found
    try:
        resolved = Path(candidate).resolve(strict=True)
    except OSError as exc:
        raise _ToolIdentityUnknown() from exc
    if resolved.is_relative_to(root):
        raise ValueError("RUNNER_TOOL_PATH_NOT_TRUSTED")
    try:
        handle = _open_held_executable(resolved)
    except OSError as exc:
        raise _ToolIdentityUnknown() from exc
    try:
        identity = _vet_tool(resolved, handle, root)
        digest = _held_digest(handle)
    except OSError as exc:
        os.close(handle)
        raise _ToolIdentityUnknown() from exc
    except BaseException:
        os.close(handle)
        raise
    return _TrustedTool(str(resolved), handle, identity, digest)


def _vet_tool(resolved: Path, handle: int, root: Path) -> tuple[int, int, int, int]:
    """The opened executable must be a plain file, identical to its path, with no alias under ``root``."""

    try:
        held, link = os.fstat(handle), os.lstat(resolved)
        if _classify(link) != "file" or _identity(link) != _identity(held):
            raise _ToolIdentityUnknown()
        if held.st_nlink < 1 or held.st_dev == 0 or held.st_ino == 0:
            raise _ToolIdentityUnknown()
        if held.st_nlink > 1 and _root_holds_identity(root, held.st_dev, held.st_ino):
            raise ValueError("RUNNER_TOOL_PATH_NOT_TRUSTED")
    except OSError as exc:
        raise _ToolIdentityUnknown() from exc
    return _identity(held)


def _observe_subject(entry: Path, root: Path) -> dict[str, Any]:
    """Type, identity, metadata and content digest of the selected entry, read before and after the process.

    Only the selected entry is observed; other files the subject reads or writes are not monitored.
    """

    relative = entry.relative_to(root).as_posix()
    try:
        before_open = os.lstat(entry)
        if not stat.S_ISREG(before_open.st_mode):
            return {"state": "NOT_REGULAR_FILE", "relative_path": relative}
        digest = hashlib.sha256()
        with open(entry, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino) != (before_open.st_dev, before_open.st_ino):
                return {"state": "UNSTABLE_OBSERVATION", "relative_path": relative}
            for chunk in iter(lambda: handle.read(_CHUNK), b""):
                digest.update(chunk)
    except OSError:
        return {"state": "UNOBSERVABLE", "relative_path": relative}
    return {"state": "OBSERVED", "relative_path": relative, "sha256": digest.hexdigest(),
            "size": opened.st_size, "mtime_ns": opened.st_mtime_ns, "ctime_ns": opened.st_ctime_ns,
            "mode": stat.S_IMODE(opened.st_mode), "device": opened.st_dev, "inode": opened.st_ino}


@contextmanager
def _no_cwd_exe_search() -> Iterator[None]:
    """Windows only: the child's executable search skips the current directory, for this call only.

    The variable is set in this process because subprocess inherits the parent environment when
    no env is passed. Its previous value is restored on exit, including on error.
    """

    if sys.platform != "win32":
        yield
        return
    previous = os.environ.get(_NO_CWD_EXE_SEARCH)
    os.environ[_NO_CWD_EXE_SEARCH] = "1"
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(_NO_CWD_EXE_SEARCH, None)
        else:
            os.environ[_NO_CWD_EXE_SEARCH] = previous


@dataclass(frozen=True)
class _StaticExtension:
    """One explicitly named optional distribution; never a host-wide plugin scan."""

    name: str
    package: str

    def load(self) -> Any:
        if self.package == "vstd_languages":
            from vstd_languages import command

            return command
        if self.package == "vstd_openshell":
            from vstd_openshell import run

            return run
        raise ImportError("RUNNER_EXTENSION_PACKAGE_UNSUPPORTED")


def _extensions() -> list[Any]:
    """Describe the one supported language package without importing it."""

    if find_spec("vstd_languages") is None:
        return []
    return [_StaticExtension(name, "vstd_languages") for name in sorted(_AVAILABLE)]


def _sandbox_extensions() -> list[Any]:
    """Describe the one supported sandbox package without importing it."""

    return ([] if find_spec("vstd_openshell") is None
            else [_StaticExtension("openshell", "vstd_openshell")])


def language_catalog() -> dict[str, Any]:
    return {"schema_version": PROTOCOL, "status": "PASS", "default_language": "python",
            "ranking_basis": "TIOBE October 2026 positions 2-25; supplements are not ranked",
            "languages": [{"language": language, "suffixes": list(suffixes),
                "cohort": "builtin" if language == "python" else (
                    "top24-extension-target" if language in dict(_TARGETS) else "paradigm-supplement"),
                "runner_status": "TRUSTED_LOCAL_PROCESS_ONLY" if language == "python" else (
                    "EXTENSION_AVAILABLE" if language in _AVAILABLE else "NOT_IMPLEMENTED"),
                "qualification": "NOT_ESTABLISHED"}
                for language, suffixes in _SUFFIXES.items()],
            "claim_boundary": "Twenty-five native adapters in the optional language package, twenty-three of the top-24 targets; Classic Visual Basic and TypeScript remain unimplemented. Availability is not installation, toolchain availability or obligation qualification."}


def detect_languages(root: str | Path, *, max_files: int = 20000,
                     max_directories: int = _DIRECTORY_VISIT_BOUND) -> dict[str, Any]:
    selected = Path(root).resolve(strict=True)
    if (not selected.is_dir() or type(max_files) is not int or not 1 <= max_files <= 100000
            or type(max_directories) is not int or not 1 <= max_directories <= 100000):
        raise ValueError("RUNNER_DISCOVERY_SCOPE_INVALID")
    counts: dict[str, int] = {}
    seen = ambiguous = skipped_links = skipped_reparse = unobservable = excluded = 0
    excluded_names: set[str] = set()
    bounded = False
    walk = _walk(str(selected), max_directories=max_directories, exclude=_EXCLUDED)
    try:
        for path, kind, _ in walk:
            if kind == "bounded":
                bounded = True
                break
            if kind == "unobservable":
                unobservable += 1
            elif kind == "excluded":
                # A policy exclusion: the named tree is not inspected, so the scope is not whole-repository.
                excluded += 1
                excluded_names.add(Path(path).name)
            elif kind == "symlink":
                skipped_links += 1
            elif kind == "reparse":
                skipped_reparse += 1
            else:
                if seen >= max_files:
                    bounded = True
                    break
                seen += 1
                candidates = [language for language, suffixes in _SUFFIXES.items() if Path(path).suffix.lower() in suffixes]
                ambiguous += len(candidates) > 1
                for language in candidates:
                    counts[language] = counts.get(language, 0) + 1
    finally:
        walk.close()
    incomplete = bounded or unobservable > 0
    return {"schema_version": PROTOCOL, "status": "UNKNOWN" if incomplete else "PASS",
            "languages": dict(sorted(counts.items())), "ambiguous_file_count": ambiguous,
            "examined_file_count": seen, "symlinks_skipped": skipped_links,
            "reparse_points_skipped": skipped_reparse, "unobservable_entry_count": unobservable,
            "coverage_scope": "DECLARED_DISCOVERY_SCOPE", "excluded_directories_skipped": excluded,
            "excluded_directory_names_skipped": sorted(excluded_names),
            "whole_repo_complete": not incomplete and excluded == 0,
            "directory_visit_bound": max_directories, "excluded_directory_names": sorted(_EXCLUDED),
            "capacity_reached": bounded, "execution_performed": False,
            "claim_boundary": "Filename candidates only, not semantic language, exposed-object coverage or runtime availability. Coverage is the declared discovery scope: named excluded directories were not inspected, so whole_repo_complete is false when any were skipped. Explicit execution selection is still required."}


def sandbox_requirements(kind: str, activity: str, continuity: bool) -> dict[str, Any]:
    selected = "MODEL" if activity == "train" else kind
    if selected not in _PROFILE_NAMES:
        raise ValueError("RUNNER_OBJECT_KIND_UNSUPPORTED")
    corrigibility = {"MODEL": "REQUIRED_NOT_ESTABLISHED", "BOT": "REQUIRED_NOT_ESTABLISHED",
                      "AGENT": "NOT_ASSUMED_OPEN_ENDED", "SIM": "CONDITIONAL_REQUIRES_REASON",
                      "OBJECT": "NOT_ASSESSED"}[selected]
    controls = [] if selected == "OBJECT" else ["filesystem-boundary", "network-policy", "process-tree-ownership",
                                               "resource-bounds", "policy-and-runtime-binding", "escape-negative-controls"]
    if selected in {"MODEL", "BOT"}:
        controls += ["authorized-intervention", "checkpoint-integrity", "corrigibility-evidence"]
    if selected == "BOT":
        controls += ["exact-sim-binding", "sim-channel-confinement", "harness-binding"]
    if selected == "SIM":
        controls += ["containment-independent-of-workload-liveness", "declared-lifecycle-policy"]
    if continuity:
        controls += ["bounded-failure-model", "redundant-capacity", "failover-and-recovery-evidence"]
    return {"name": _PROFILE_NAMES[selected], "object_kind": kind, "activity": activity,
            "corrigibility": corrigibility, "required_controls": controls,
            "availability": "REQUIRED_NOT_ESTABLISHED" if continuity else "NOT_CLAIMED",
            "qualification": "NOT_ESTABLISHED"}


def _observed_parent_process_started(receipt: dict[str, Any]) -> str:
    """Read the capture-owned process state without inferring child execution."""

    try:
        observation = receipt["assessment_context"]["refutation_surface"][
            "parent_process_observation"
        ]
        process_started = observation["result"]["process_started"]
    except (KeyError, TypeError) as exc:
        raise ValueError("RUNNER_PROCESS_OBSERVATION_MISSING") from exc
    if process_started not in {"YES", "NO", "UNKNOWN"}:
        raise ValueError("RUNNER_PROCESS_OBSERVATION_INVALID")
    return process_started


def _integrity(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Selected-entry observations: ``before`` precedes any adapter or backend hook, ``after`` follows the run."""

    return {"status": "CHANGED" if before != after else "UNCHANGED", "scope": "selected_entry_only",
            "baseline": "before_adapter_or_backend_hook", "before": before, "after": after}


def _bound_observation(before: dict[str, Any], after: dict[str, Any]) -> bool:
    """Only two established and identical observations bind a PASS; equal UNOBSERVABLE states do not."""

    return before.get("state") == after.get("state") == "OBSERVED" and before == after


def _assess_runner(args: argparse.Namespace) -> dict[str, Any]:
    report: dict[str, Any] = {"schema_version": PROTOCOL, "status": "UNKNOWN", "language": args.language,
        "selection": "EXPLICIT" if args.language != "python" else "PYTHON_DEFAULT_OR_EXPLICIT",
        "profile": sandbox_requirements(args.object_kind, args.activity, args.continuity_required),
        "sandbox_status": "NOT_ESTABLISHED", "obligation_status": "UNKNOWN", "polished": False,
        "execution_performed": False, "execution_attempted": False, "receipt": None, "blockers": [],
        "claim_boundary": "Execution receipt only. No security sandbox, object conformance, corrigibility or availability inferred."}
    try:
        root = Path(args.root).resolve(strict=True)
        entry = (root / args.entry).resolve()
        if not entry.is_relative_to(root):
            raise ValueError("RUNNER_ENTRY_OUTSIDE_ROOT")
        if not entry.is_file():
            report["blockers"].append("RUNNER_ENTRY_MISSING")
            return report
        matches = [lang for lang, suffixes in _SUFFIXES.items() if entry.suffix.lower() in suffixes]
        if matches and args.language not in matches:
            raise ValueError("RUNNER_LANGUAGE_SELECTION_DIFFERS")
        extensions = [] if args.language == "python" else [item for item in _extensions() if item.name == args.language]
        if len(extensions) > 1:
            raise ValueError("RUNNER_EXTENSION_SELECTION_AMBIGUOUS")
        if args.language != "python" and not extensions:
            report["blockers"].append("RUNNER_EXTENSION_NOT_INSTALLED")
        backends = []
        if args.sandbox == "openshell":
            backends = [item for item in _sandbox_extensions()
                        if item.name == "openshell"]
            if len(backends) > 1:
                raise ValueError("RUNNER_SANDBOX_EXTENSION_AMBIGUOUS")
            if not backends:
                report["blockers"].append("RUNNER_SANDBOX_EXTENSION_NOT_INSTALLED")
            if not args.sandbox_config:
                report["blockers"].append("RUNNER_SANDBOX_CONFIG_REQUIRED")
        elif report["profile"]["required_controls"]:
            report["blockers"].append("RUNNER_ISOLATION_BACKEND_NOT_QUALIFIED")
        if args.sandbox == "none" and not args.trusted_local:
            report["blockers"].append("RUNNER_TRUSTED_LOCAL_SELECTION_REQUIRED")
        if type(args.timeout) is not int or not 1 <= args.timeout <= 3600:
            raise ValueError("RUNNER_TIMEOUT_INVALID")
        report["entry"] = entry.relative_to(root).as_posix()
        report["extension_status"] = "BUILTIN" if args.language == "python" else (
            "INSTALLED_NOT_LOADED" if extensions else "NOT_INSTALLED")
        if args.runner_command == "plan" or report["blockers"]:
            return report
        # The baseline comes first: the selected entry is observed before any adapter or backend is imported or called.
        subject_before = _observe_subject(entry, root)
        if subject_before["state"] != "OBSERVED":
            # No observed baseline: nothing can be bound to a PASS, so no adapter, backend or process is called.
            report["blockers"].append("RUNNER_SUBJECT_OR_REMOTE_EXECUTION_FAILED")
            return report
        request = {"schema_version": PROTOCOL, "language": args.language,
                   "root": "/sandbox/source" if backends else str(root),
                   "entry": report["entry"], "arguments": list(args.argument)}
        if backends:
            request["environment"] = "sandbox-linux"
        if args.language == "python":
            command = (["python3", "-B", "/sandbox/source/" + report["entry"], *args.argument]
                       if backends else [sys.executable, "-B", str(entry), *args.argument])
        else:
            # An explicitly selected, installed extension is trusted local code.
            # Detection and planning never call load() or an extension.
            extension = extensions[0].load()
            report["extension_status"] = "LOADED"
            response = extension(request)
            if (type(response) is not dict or set(response) != {"schema_version", "language", "argv"}
                    or response["schema_version"] != PROTOCOL or response["language"] != args.language):
                raise ValueError("RUNNER_EXTENSION_PROTOCOL_DIFFERS")
            command = response["argv"]
        if (type(command) is not list or not 1 <= len(command) <= 256
                or any(type(arg) is not str or not arg or "\0" in arg or len(arg) > 8192 for arg in command)):
            raise ValueError("RUNNER_ARGUMENT_VECTOR_INVALID")
        if backends:
            backend = backends[0].load()
            report["execution_attempted"] = True
            result = backend({"schema_version": "verifier-sandbox-request-1", "root": str(root),
                "entry": report["entry"], "inputs": list(args.input), "argv": command,
                "timeout": args.timeout, "profile": report["profile"],
                "config": str(Path(args.sandbox_config).resolve(strict=True))})
            if (type(result) is not dict or result.get("schema_version") != "verifier-openshell-result-1"
                    or result.get("status") not in {"PASS", "FAIL", "UNKNOWN"}
                    or (result.get("execution_performed") is not None and type(result["execution_performed"]) is not bool)
                    or type(result.get("blockers", [])) is not list):
                raise ValueError("RUNNER_SANDBOX_PROTOCOL_DIFFERS")
            subject_after = _observe_subject(entry, root)
            report["receipt"] = result
            report["status"] = result["status"]
            report["execution_performed"] = result["execution_performed"]
            report["sandbox_status"] = result.get("sandbox_status", "NOT_ESTABLISHED")
            report["subject_integrity"] = _integrity(subject_before, subject_after)
            # Backend blocker text is untrusted: only the closed vocabulary passes verbatim.
            report["blockers"].extend(item if type(item) is str and item in _BLOCKER_CODES
                                      else "RUNNER_SANDBOX_PROTOCOL_DIFFERS"
                                      for item in result.get("blockers", []))
            if subject_after != subject_before:
                # The backend result is not bound to one source when the entry changed around it.
                report["blockers"].append("RUNNER_SUBJECT_SOURCE_CHANGED")
            if not _bound_observation(subject_before, subject_after):
                report["status"] = "UNKNOWN"
            report["claim_boundary"] = "Optional backend process and bounded containment observations only; object obligations, corrigibility and availability remain UNKNOWN."
            return report
        from verifier.core.run import capture_run
        # Bind the actual host-side argv[0], including the default Python interpreter,
        # before the subject root becomes the working directory. A language choice and
        # an executable identity are separate claims; neither may stand in for the other.
        tool = _trusted_executable(command[0], root)
        try:
            if tool is not None:
                command = [tool.path, *command[1:]]
                report["tool_binding"] = tool.describe()
            subject_launch = _observe_subject(entry, root)
            if subject_launch != subject_before:
                report["subject_integrity"] = _integrity(subject_before, subject_launch)
                report["blockers"].append("RUNNER_SUBJECT_SOURCE_CHANGED")
                return report
            if tool is not None:
                # Nothing has launched yet, so a tool that is not bound (changed, or not re-readable) is refused here.
                tool_state = tool.still_bound()
                if tool_state != "BOUND":
                    report["blockers"].append("RUNNER_TOOL_IDENTITY_CHANGED" if tool_state == "CHANGED"
                                              else "RUNNER_TOOL_IDENTITY_UNKNOWN")
                    return report
            report["execution_attempted"] = True
            with _no_cwd_exe_search():
                receipt = capture_run({"command": command, "cwd": ".", "repo_dir": ".",
                    "inputs": [{"path": report["entry"], "role": "source"}], "outputs": [],
                    "timeout_seconds": args.timeout,
                    "claim": {"id": "LANGUAGE-RUN", "statement": "Selected trusted-local process exit only.",
                              "limitations": [report["claim_boundary"]]}}, root)
            # Post-run state is read before the handle is closed; it is not inferred from the exit code.
            tool_state = tool.still_bound() if tool is not None else "BOUND"
        finally:
            if tool is not None:
                tool.close()
        subject_after = _observe_subject(entry, root)
        receipt_data = receipt.to_dict()
        process_started = _observed_parent_process_started(receipt_data)
        report["execution_performed"] = {
            "YES": True,
            "NO": False,
            "UNKNOWN": None,
        }[process_started]
        report["receipt"] = receipt_data
        # The receipt keeps the pre-run digest; the post-run observation is reported beside it, never written into it.
        report["subject_integrity"] = _integrity(subject_before, subject_after)
        if subject_after != subject_before:
            # A subject that rewrote its own entry cannot be bound to a PASS, whatever its exit code.
            report["blockers"].append("RUNNER_SUBJECT_SOURCE_CHANGED")
        if tool_state == "CHANGED":
            report["blockers"].append("RUNNER_TOOL_IDENTITY_CHANGED")
        elif tool_state == "UNKNOWN":
            report["blockers"].append("RUNNER_TOOL_IDENTITY_UNKNOWN")
        exit_code = receipt.execution.exit_code
        # Exact type only: bool and float compare equal to integers in Python, but neither is a
        # process exit status. Reject them before both reserved lookup and the zero/PASS branch.
        exit_code_valid = exit_code is None or type(exit_code) is int
        if not exit_code_valid:
            report["blockers"].append("RUNNER_PROCESS_OBSERVATION_INVALID")
        # Python keeps its historical exact-integer exit semantics.
        reserved = (_EXTENSION_EXIT_BLOCKERS.get(exit_code)
                    if args.language != "python" and type(exit_code) is int else None)
        if reserved is not None:
            report["blockers"].append(reserved)
        if (not exit_code_valid or not _bound_observation(subject_before, subject_after)
                or tool_state != "BOUND" or reserved is not None):
            report["status"] = "UNKNOWN"
        else:
            report["status"] = "PASS" if exit_code == 0 else ("UNKNOWN" if exit_code is None else "FAIL")
    except _ToolIdentityUnknown:
        # Nothing was launched: the executable's identity was not established, so no outcome is claimed.
        report["blockers"].append("RUNNER_TOOL_IDENTITY_UNKNOWN")
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError) as exc:
        report["blockers"].append(_resource_blocker(exc))
        if report["execution_attempted"]:
            report["execution_performed"] = None
    except (ValueError, KeyError, TypeError, AttributeError, RuntimeError) as exc:
        report["blockers"].append(_contract_blocker(exc))
        if report["execution_attempted"]:
            # A contract or normalization failure after the launch was requested does not establish a failed run.
            report["status"] = "UNKNOWN"
            report["execution_performed"] = None
        else:
            report["status"] = "FAIL"
    except Exception:
        # Unclassified: its text is not trusted and the outcome is not established, so it stays UNKNOWN.
        report["blockers"].append("RUNNER_EXCEPTION_UNCLASSIFIED")
        if report["execution_attempted"]:
            report["execution_performed"] = None
    except BaseException as exc:
        # Host cancellation propagates unchanged. Other control flow that an adapter or backend uses
        # to end the host (SystemExit, or a non-Exception BaseException) is closed as UNKNOWN; its payload is never read.
        # The type is tested directly: isinstance() would consult a hostile __class__ property.
        if issubclass(type(exc), (KeyboardInterrupt, GeneratorExit)):
            raise
        report["blockers"].append("RUNNER_ADAPTER_TERMINATED")
        if report["execution_attempted"]:
            report["execution_performed"] = None
    return report


# Closed guidance: one (reason, next_action) pair per blocker code. Text is fixed printable
# American Standard Code for Information Interchange (ASCII) under 180 characters and never built from exception text, paths or backend output.
# The drift test requires an entry for every code in _BLOCKER_CODES.
_BLOCKER_GUIDANCE: dict[str, tuple[str, str]] = {
    "RUNNER_ADAPTER_TERMINATED": ("The language adapter ended the host process path before returning a response; its exit payload is not reproduced.",
        "Install an adapter version that returns a verifier-language-runner-1 response instead of exiting; the runner does not read exit payloads."),
    "RUNNER_ARGUMENT_INVALID": ("The language adapter rejected an entry argument.",
        "Pass only argument values the adapter accepts; use --argument=VALUE for values beginning with a hyphen."),
    "RUNNER_ARGUMENT_VECTOR_INVALID": ("The command vector is not a bounded list of nonempty strings.",
        "Correct the adapter argv contract: 1 to 256 nonempty strings, no NUL, at most 8192 characters each."),
    "RUNNER_BOT_EXACT_BINDINGS_REQUIRED": ("The BOT profile needs exact simulation and harness bindings that were not supplied.",
        "Supply exact BOT binding evidence; --trusted-local and the basic process path cannot satisfy BOT."),
    "RUNNER_CONTRACT_REJECTED": ("A runner or adapter contract check rejected the request; the check text is not reproduced.",
        "Compare the request with the runner contract shown by the catalog command and the language runner standard, then rerun."),
    "RUNNER_DIALECT_UNSUPPORTED": ("The adapter does not support the requested language dialect.",
        "Use a dialect the adapter declares in its documentation, or select a different installed adapter version."),
    "RUNNER_DISCOVERY_SCOPE_INVALID": ("The detection root is not an existing directory or the file bound is invalid.",
        "Pass an existing directory as the detect root; the command uses the library's default file bound."),
    "RUNNER_ENTRY_INVALID": ("The language adapter rejected the entry path.",
        "Pass a repository-relative entry file whose suffix belongs to the selected language."),
    "RUNNER_ENTRY_MISSING": ("The entry is not an existing regular file under the root.",
        "Pass an existing regular file as the entry, relative to --root."),
    "RUNNER_ENTRY_OUTSIDE_ROOT": ("The entry resolves outside the selected root.",
        "Move the entry under --root, or choose a --root that contains it; links resolving outside the root are rejected."),
    "RUNNER_ENVIRONMENT_UNSUPPORTED": ("The language adapter does not support the requested execution environment.",
        "Run without --sandbox openshell for trusted-local execution, or use an adapter that declares sandbox-linux support."),
    "RUNNER_EXCEPTION_UNCLASSIFIED": ("An unclassified failure occurred; its text is not trusted, so the outcome is not established.",
        "Rerun with the same arguments; if it recurs, record the closed report and inspect the runner code path, not any message text."),
    "RUNNER_EXTENSION_EXIT_OUTPUT_CAPACITY": ("The extension worker exited with reserved code 125; the receipt identifies neither the bounded stage nor a natural code collision.",
        "Inspect the extension's declared bounds and receipt, then reduce the relevant output or choose a suitable adapter; core does not infer the stage."),
    "RUNNER_EXTENSION_EXIT_RESOURCE_UNAVAILABLE": ("The extension worker exited with its reserved resource code 126, named for an unavailable resource or failed spawn; the failing step is not reported.",
        "Confirm the resources and toolchain the worker needs exist and are executable on this host, then rerun; the runner never installs them."),
    "RUNNER_EXTENSION_EXIT_TIMEOUT": ("The extension worker exited with reserved code 124; the receipt identifies neither the timed stage nor a natural code collision.",
        "Inspect the extension's declared stage limits and receipt, then reduce the bounded work or choose a suitable adapter; --timeout is not proven causal."),
    "RUNNER_EXTENSION_EXIT_TOOLCHAIN_UNAVAILABLE": ("The extension worker exited with its reserved toolchain code 127, named for an unavailable toolchain or version; the tool is not named.",
        "Install or expose the toolchain version the adapter declares so it resolves on PATH, then rerun; the runner never installs toolchains."),
    "RUNNER_EXTENSION_NOT_INSTALLED": ("The selected language has no installed adapter in this environment.",
        "No installed adapter declares this language; choose a language the catalog marks EXTENSION_AVAILABLE."),
    "RUNNER_EXTENSION_PACKAGE_UNSUPPORTED": ("The requested extension package is not one of the fixed packaged adapters.",
        "Use only the packaged adapters named in the language runner standard; the runner never loads other packages."),
    "RUNNER_EXTENSION_PROTOCOL_DIFFERS": ("The adapter response does not match verifier-language-runner-1 for the selected language.",
        "Install an adapter version that matches this core; the runner does not repair adapter output."),
    "RUNNER_EXTENSION_SELECTION_AMBIGUOUS": ("More than one installed adapter claims the selected language.",
        "Uninstall the duplicate adapter so exactly one provider remains for this language."),
    "RUNNER_ISOLATION_BACKEND_NOT_QUALIFIED": ("The selected object profile needs an isolation backend, which the basic process path cannot provide.",
        "Select --sandbox openshell with the optional vstd-openshell package and --sandbox-config; --trusted-local never satisfies a nonbasic profile."),
    "RUNNER_LANGUAGE_SELECTION_DIFFERS": ("The entry suffix belongs to a different language than the one selected.",
        "Rerun with --language matching the entry suffix; the default python never auto-detects a language."),
    "RUNNER_LANGUAGE_UNSUPPORTED": ("The language adapter does not implement the requested language.",
        "Choose a language the catalog marks EXTENSION_AVAILABLE, or use the default python for the trusted-local basic path."),
    "RUNNER_OBJECT_KIND_UNSUPPORTED": ("The object kind is not a declared profile kind.",
        "Pass --object-kind as one of OBJECT, MODEL, AGENT, BOT or SIM."),
    "RUNNER_OPENSHELL_CLI_MISSING": ("The OpenShell command-line tool is not available on this host.",
        "On a Linux host, install the pinned OpenShell 0.1.3 tool per the language runner standard and confirm it resolves on PATH; host execution is never a fallback."),
    "RUNNER_OPENSHELL_COMMAND_INCOMPLETE": ("The OpenShell command sequence did not complete.",
        "Check the OpenShell tool and gateway state on the Linux host, then rerun; the receipt records which step did not complete."),
    "RUNNER_OPENSHELL_EXECUTION_INCOMPLETE": ("OpenShell execution did not complete, so containment and outcome are not established.",
        "Inspect the backend receipt, clear the named cause, and rerun with --sandbox openshell; do not treat the partial run as evidence."),
    "RUNNER_OPENSHELL_GATEWAY_NOT_REGISTERED": ("No OpenShell gateway is registered for the configured endpoint.",
        "Register or start the local authenticated OpenShell gateway, then rerun; the runner never selects a gateway automatically."),
    "RUNNER_OPENSHELL_GATEWAY_VERSION_OR_HEALTH_DIFFERS": ("The OpenShell gateway version or health differs from the required state.",
        "Restart the local OpenShell gateway at the pinned version and confirm it reports healthy, then rerun."),
    "RUNNER_OPENSHELL_UNAVAILABLE_OR_INVALID_RESPONSE": ("OpenShell was unavailable or returned an invalid response; its text is not reproduced.",
        "Confirm the local gateway answers its health check, then rerun the optional path."),
    "RUNNER_OPENSHELL_VERSION_DIFFERS": ("The OpenShell version differs from the pinned 0.1.3.",
        "Install the pinned OpenShell 0.1.3, then rerun the optional path."),
    "RUNNER_PROCESS_OBSERVATION_INVALID": ("The capture-owned process observation or exit status has an unrecognized shape or value.",
        "Treat the process outcome as UNKNOWN and inspect the receipt; do not correct the observation by hand."),
    "RUNNER_PROCESS_OBSERVATION_MISSING": ("The process receipt has no parent process observation.",
        "Rerun with the current core; the execution state cannot be read from this receipt."),
    "RUNNER_RECEIPT_WRONG_VERSION": ("The backend receipt declares an unsupported version.",
        "Use an adapter or backend whose receipt version matches this core."),
    "RUNNER_RESOURCE_UNAVAILABLE": ("A required file, directory or runtime resource was unavailable; its path is not reproduced.",
        "Confirm the root and entry exist and are readable, install any missing toolchain the blocker names, then rerun."),
    "RUNNER_ROOT_INVALID": ("The language adapter rejected the root.",
        "Pass an existing repository root directory to --root."),
    "RUNNER_SANDBOX_BINDING_CHANGED": ("The sandbox binding changed between admission and execution.",
        "Rerun from a stable checkout so the admitted binding matches the executed one."),
    "RUNNER_SANDBOX_CLEANUP_NOT_ESTABLISHED": ("Sandbox cleanup was not confirmed after the run.",
        "Inspect and remove the optional sandbox resources the receipt names; cleanup must be verified before reliance."),
    "RUNNER_SANDBOX_CLEANUP_OWNERSHIP_DIFFERS": ("Sandbox cleanup ownership does not match the resources the runner created.",
        "Verify sandbox resource ownership; the runner never removes resources it did not create."),
    "RUNNER_SANDBOX_CONFIG_CAPACITY": ("The --sandbox-config file exceeds its size bound.",
        "Reduce --sandbox-config to the bounded fields the optional backend documents."),
    "RUNNER_SANDBOX_CONFIG_FIELDS": ("The --sandbox-config file has missing or unexpected fields.",
        "Correct --sandbox-config to the documented field set, then rerun."),
    "RUNNER_SANDBOX_CONFIG_REQUIRED": ("--sandbox openshell was selected without --sandbox-config.",
        "Pass an explicit --sandbox-config path; the runner never selects a gateway automatically."),
    "RUNNER_SANDBOX_CONFIG_VERSION": ("The --sandbox-config version is not accepted by this core.",
        "Regenerate --sandbox-config at the version the language runner standard names."),
    "RUNNER_SANDBOX_CONTINUITY_NOT_IMPLEMENTED": ("Continuity was requested, but the sandbox path does not implement it.",
        "Remove --continuity-required for this run; continuity evidence needs a separate mechanism and is not claimed here."),
    "RUNNER_SANDBOX_DELETE_NOT_ESTABLISHED": ("Deletion of the sandbox was not confirmed.",
        "Verify with the optional backend's tooling that the sandbox was removed; deletion is never inferred."),
    "RUNNER_SANDBOX_DUPLICATE_KEY": ("The sandbox configuration repeats a key.",
        "Remove the duplicate key so each field appears once in --sandbox-config."),
    "RUNNER_SANDBOX_EFFECTIVE_POLICY_DIFFERS": ("The effective sandbox policy differs from the requested policy.",
        "Align --sandbox-config with what the backend enforces, then rerun."),
    "RUNNER_SANDBOX_EXTENSION_AMBIGUOUS": ("More than one sandbox backend claims the openshell name.",
        "Uninstall the duplicate vstd-openshell provider so exactly one remains."),
    "RUNNER_SANDBOX_EXTENSION_NOT_INSTALLED": ("The optional OpenShell backend is not installed.",
        "On a Linux checkout run: python -m pip install ./extensions/openshell (distribution vstd-openshell), then rerun with --sandbox-config."),
    "RUNNER_SANDBOX_IDENTITY_OR_READINESS_DIFFERS": ("The sandbox identity or readiness differs from the admitted state.",
        "Restart the optional sandbox from a clean state and rerun; the runner never reuses a sandbox."),
    "RUNNER_SANDBOX_IMAGE_MUST_BE_DIGEST_PINNED": ("The sandbox image is not pinned by content digest.",
        "Set the image in --sandbox-config to a content digest rather than a mutable tag."),
    "RUNNER_SANDBOX_INPUT_CAPACITY": ("The --input set exceeds the sandbox input bound.",
        "Pass fewer or smaller --input files; the runner never uploads the whole repository."),
    "RUNNER_SANDBOX_INPUT_OUTSIDE_ROOT": ("An --input path resolves outside the root.",
        "Pass --input paths that resolve under --root."),
    "RUNNER_SANDBOX_INPUT_PATH_INVALID": ("An --input path is not a valid repository-relative file.",
        "Pass each --input as a repository-relative path to a regular file."),
    "RUNNER_SANDBOX_INPUT_SYMLINK": ("An --input path is a symbolic link.",
        "Pass the regular file itself; symbolic links are not copied into a sandbox."),
    "RUNNER_SANDBOX_LIFECYCLE_UNSUPPORTED": ("The requested sandbox lifecycle is not supported by the backend.",
        "Choose a lifecycle the backend declares, or remove the lifecycle request."),
    "RUNNER_SANDBOX_NEGATIVE_CONTROLS_NOT_ESTABLISHED": ("Escape negative controls were not run, so containment is not established.",
        "Run the optional backend's negative-control suite and rerun; sandbox status stays NOT_ESTABLISHED until it passes."),
    "RUNNER_SANDBOX_NEGATIVE_CONTROL_FAILED": ("A sandbox escape negative control failed.",
        "Treat the sandbox as unqualified and repair the backend configuration before any further run."),
    "RUNNER_SANDBOX_POLICY_ADMISSION_NOT_ESTABLISHED": ("The sandbox policy was not admitted.",
        "Admit the policy through the optional backend's documented admission step, then rerun."),
    "RUNNER_SANDBOX_PROTOCOL_DIFFERS": ("The sandbox backend response does not match its protocol or declared blocker codes.",
        "Install an optional backend version that matches this core; the runner does not repair its response."),
    "RUNNER_SANDBOX_REQUEST_VERSION": ("The sandbox request version is not supported.",
        "Use a backend that accepts verifier-sandbox-request-1."),
    "RUNNER_SANDBOX_RESOURCE_BOUND_INVALID": ("A sandbox resource bound is missing or outside its allowed range.",
        "Set the resource bound in --sandbox-config within its documented range."),
    "RUNNER_SANDBOX_SCOPE_REASON_REQUIRED": ("The sandbox scope requires a stated reason.",
        "Add the required scope reason to --sandbox-config."),
    "RUNNER_SANDBOX_SOURCE_BINDING_DIFFERS": ("The source binding differs from the admitted source.",
        "Rerun from the admitted source revision with no edits in between."),
    "RUNNER_SANDBOX_SOURCE_CHANGED": ("The source changed after admission.",
        "Re-admit the entry from the unchanged source, then rerun."),
    "RUNNER_SANDBOX_STAGING_UNAVAILABLE": ("The staged sandbox source could not be prepared.",
        "Confirm the optional backend's staging location is available and writable, then rerun."),
    "RUNNER_SANDBOX_STOP_NOT_ESTABLISHED": ("Stopping the sandbox was not confirmed.",
        "Stop the sandbox with the optional backend's tooling and verify it has exited before reliance."),
    "RUNNER_SANDBOX_TARGET_INVALID": ("The sandbox target is invalid.",
        "Set the --sandbox-config target to a valid target for the optional backend."),
    "RUNNER_SANDBOX_UNEXPECTED_NETWORK_GRANT": ("The sandbox received a network grant the profile does not allow.",
        "Remove the network grant from --sandbox-config so the policy matches the profile's network-policy control."),
    "RUNNER_SUBJECT_OR_REMOTE_EXECUTION_FAILED": ("The subject or remote execution failed before a result was established; with no observed baseline, nothing was launched.",
        "Inspect the receipt and subject_integrity fields, correct the named subject or remote fault, and rerun."),
    "RUNNER_SUBJECT_SOURCE_CHANGED": ("The selected entry changed before launch, during the run, or around a backend call, so the result is not bound to one source.",
        "Restore a stable entry and rerun; the original receipt is kept unchanged and this run is not a PASS for any source."),
    "RUNNER_TIMEOUT_INVALID": ("--timeout is outside 1 to 3600 seconds.",
        "Pass --timeout as an integer from 1 to 3600."),
    "RUNNER_TOOL_IDENTITY_CHANGED": ("The adapter-named executable changed after it was bound, so the launch or its result is not tied to the verified binary.",
        "Install a stable executable outside --root, leave it unchanged during the run, and rerun; the runner never re-resolves a changed tool."),
    "RUNNER_TOOL_IDENTITY_UNKNOWN": ("The adapter-named executable's identity could not be established on this host, so nothing was launched.",
        "Place the tool at a stable absolute path outside --root on a filesystem that reports file identity, then rerun; the runner never guesses."),
    "RUNNER_TOOL_PATH_NOT_TRUSTED": ("The adapter-named executable is a relative path, resolves inside the subject root, or is a hard-link alias of a file under the root, so the runner refuses to run it.",
        "Name a tool installed in an absolute PATH directory outside --root, or give an absolute path outside --root; the runner never runs subject-provided executables."),
    "RUNNER_TOOLCHAIN_VERSION_UNKNOWN": ("The installed toolchain version could not be established.",
        "Install or expose a toolchain whose version can be read, then rerun."),
    "RUNNER_TRUSTED_LOCAL_SELECTION_REQUIRED": ("Unsandboxed execution was requested without an explicit trusted-local selection.",
        "Add --trusted-local only if the entry is trusted local code; otherwise use the optional sandbox path."),
}
_UNCLASSIFIED_BLOCKER = ("A blocker outside the closed vocabulary was reported; its text is not reproduced.",
                         "Rerun with the current core; if it persists, inspect the component that reported it.")
_UNCLASSIFIED_OUTCOME = ("The outcome matches no classified state, so it is not established.",
                         "Rerun with --json and inspect the closed report; no runner repair is established.")
_SCOPE_GUIDANCE: dict[tuple[str, Any], tuple[str, str]] = {
    ("catalog", "PASS"): ("The catalog lists declared adapter targets; installed availability and qualification are not established.",
        "No runner repair is required. Install an optional adapter only for a target you need; qualification stays NOT_ESTABLISHED."),
    ("detect", "PASS"): ("Filename candidates were counted in the declared discovery scope without importing or executing repository code; named excluded directories were not inspected.",
        "No runner repair is required. Select an explicit --language with plan or run; detection never chooses one."),
    ("detect", "UNKNOWN"): ("Detection reached its file bound, so the counts are incomplete.",
        "Narrow the root to a subdirectory and rerun; the command does not expose the file bound."),
    ("plan", "UNKNOWN"): ("Planning checked the entry, language selection and profile; nothing was executed.",
        "Run the same arguments with the run command to execute; obligation status stays UNKNOWN until verified separately."),
    ("process", "PASS"): ("The trusted-local entry process exited with code 0; the receipt records process exit only.",
        "No runner repair is required. This is not an obligation or conformance PASS; sandbox_status and obligation_status stay NOT_ESTABLISHED and UNKNOWN."),
    ("process", "FAIL"): ("The trusted-local entry process exited with a nonzero code; the receipt records the exit.",
        "Fix the entry so it exits 0 for its intended input, then rerun; a process exit is not an obligation verdict."),
    ("process", "UNKNOWN"): ("The trusted-local process exit status was not established (timeout or indeterminate observation).",
        "Inspect the receipt's parent_process_observation; if the timeout expired, rerun with a larger --timeout up to 3600 seconds."),
    ("sandbox", "PASS"): ("The optional sandbox backend reported PASS for its bounded process observation only.",
        "No runner repair is required. Containment beyond the receipt, obligation status and conformance remain unestablished."),
    ("sandbox", "FAIL"): ("The optional sandbox backend reported FAIL without a blocker code.",
        "Inspect the backend receipt and the explicit --sandbox-config, correct the named cause, and rerun."),
    ("sandbox", "UNKNOWN"): ("The optional sandbox backend returned UNKNOWN without a blocker code.",
        "Inspect the backend receipt; containment and outcome stay unestablished until a rerun is clean."),
}
_TEXT_BOUND = re.compile(r"[ -~]{1,240}")


def _blocker_guidance(code: Any, language: Any) -> tuple[str, str]:
    if type(code) is not str:
        return _UNCLASSIFIED_BLOCKER
    if code.startswith(_TOOLCHAIN_PREFIX):
        tool = code[len(_TOOLCHAIN_PREFIX):]
        if _TOOL_TOKEN.fullmatch(tool):
            return (f"Required toolchain '{tool}' is not available on this host.",
                    f"Install '{tool}' so it resolves on PATH, then rerun; the runner never installs toolchains.")
        return _UNCLASSIFIED_BLOCKER
    if code == "RUNNER_EXTENSION_NOT_INSTALLED" and type(language) is str and language in _AVAILABLE:
        return ("The selected language adapter package is not installed in this environment.",
                "Install the optional adapter from the source checkout: python -m pip install ./extensions/languages "
                "(distribution vstd-language-runners), then rerun.")
    return _BLOCKER_GUIDANCE.get(code, _UNCLASSIFIED_BLOCKER)


def _outcome_guidance(report: dict[str, Any], scope: str) -> tuple[str, str]:
    blockers = report.get("blockers")
    if type(blockers) is list and blockers:
        reason, action = _blocker_guidance(blockers[0], report.get("language"))
        if len(blockers) > 1:
            reason = f"{reason} {len(blockers) - 1} further blocker(s) recorded."
            action = f"{action} Then clear the remaining blockers in report order."
        return reason, action
    return _SCOPE_GUIDANCE.get((scope, report.get("status")), _UNCLASSIFIED_OUTCOME)


def _with_guidance(report: dict[str, Any], scope: str) -> dict[str, Any]:
    """Attach a bounded reason and next_action to every outcome; never echoes report text."""

    reason, action = _outcome_guidance(report, scope)
    report["reason"] = reason if _TEXT_BOUND.fullmatch(reason) else _UNCLASSIFIED_OUTCOME[0]
    report["next_action"] = action if _TEXT_BOUND.fullmatch(action) else _UNCLASSIFIED_OUTCOME[1]
    return report


def _scope(args: argparse.Namespace) -> str:
    if args.runner_command != "run":
        return args.runner_command
    return "sandbox" if args.sandbox == "openshell" else "process"


def assess_runner(args: argparse.Namespace) -> dict[str, Any]:
    return _with_guidance(_assess_runner(args), _scope(args))


def _render_failure() -> dict[str, Any]:
    """Closed UNKNOWN used when a report cannot be serialized; its content is not established."""

    return {"schema_version": PROTOCOL, "status": "UNKNOWN", "sandbox_status": "NOT_ESTABLISHED",
            "obligation_status": "UNKNOWN", "polished": False, "execution_performed": None,
            "blockers": ["RUNNER_EXCEPTION_UNCLASSIFIED"]}


def add_runner_parsers(subparsers: Any) -> None:
    parser = subparsers.add_parser("runner", help="Discover languages and select explicit language runners; no implied sandbox.")
    sub = parser.add_subparsers(dest="runner_command", required=True)
    catalog = sub.add_parser("catalog", help="List the default runner and detection/extension targets.")
    catalog.add_argument("--json", action="store_true")
    detect = sub.add_parser("detect", help="Detect filename language candidates without executing repository code.")
    detect.add_argument("root", nargs="?", default=".")
    detect.add_argument("--json", action="store_true")
    for name in ("plan", "run"):
        command = sub.add_parser(name, help="Plan or run an explicit language entry; protected profiles require an optional sandbox backend.")
        command.add_argument("entry")
        command.add_argument("--root", default=".")
        command.add_argument("--language", default="python")
        command.add_argument("--object-kind", choices=tuple(_PROFILE_NAMES), default="OBJECT")
        command.add_argument("--activity", choices=("check", "train"), default="check")
        command.add_argument("--continuity-required", action="store_true")
        command.add_argument("--sandbox", choices=("none", "openshell"), default="none")
        command.add_argument("--sandbox-config", help="Explicit optional backend configuration; no automatic gateway selection.")
        command.add_argument("--input", action="append", default=[], help="Additional repository-relative file to copy into a fresh sandbox; no implicit whole-repository upload.")
        command.add_argument("--trusted-local", action="store_true", help="Explicitly allow unsandboxed trusted code for the basic profile only.")
        command.add_argument("--timeout", type=int, default=60)
        command.add_argument("--argument", action="append", default=[], help="One entry argument; use --argument=VALUE for leading hyphens.")
        command.add_argument("--json", action="store_true")


def _dump(report: dict[str, Any], *, compact: bool) -> str:
    return json.dumps(report, sort_keys=True, indent=None if compact else 2, ensure_ascii=False, allow_nan=False)


def handle_runner_command(args: argparse.Namespace) -> int:
    try:
        report = (language_catalog() if args.runner_command == "catalog" else
                  detect_languages(args.root) if args.runner_command == "detect" else assess_runner(args))
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError) as exc:
        report = {"schema_version": PROTOCOL, "status": "UNKNOWN", "blockers": [_resource_blocker(exc)],
                  "execution_performed": False}
    except (ValueError, KeyError, TypeError, AttributeError, RuntimeError) as exc:
        report = {"schema_version": PROTOCOL, "status": "FAIL", "language": getattr(args, "language", None),
                  "blockers": [_contract_blocker(exc)], "execution_performed": False}
    except Exception:
        report = {"schema_version": PROTOCOL, "status": "UNKNOWN", "blockers": ["RUNNER_EXCEPTION_UNCLASSIFIED"],
                  "execution_performed": False}
    report = _with_guidance(report, _scope(args))
    try:
        text = _dump(report, compact=args.json)
    except (TypeError, ValueError, RecursionError, OverflowError):
        report = _with_guidance(_render_failure(), _scope(args))
        text = _dump(report, compact=args.json)
    if args.json:
        print(text)
    else:
        print(f"[{report['status']}] runner {args.runner_command}; no sandbox or obligation claim")
        print(text)
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[report["status"]]
