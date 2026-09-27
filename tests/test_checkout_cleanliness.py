"""Terminology: carriage return and line feed (CRLF); line feed (LF);
Verifier Standard (VSTD).

A fresh checkout of the committed tree has to be clean before anything runs.

`.gitattributes` declares this repository `eol=lf`. A blob that nevertheless
carries a carriage return inside a file declared that way is rewritten by git's
own normalization the moment it is read back, so `git worktree add --detach`
followed by `git status` reports the file modified before a single command has
executed. The local suite never notices, because every test runs against the
working copy and the working copy is the thing that was normalized. What fails
is the hosted `presentation` job, where `scripts/build_component_index.py`
refuses to address a component index to a commit whose checkout is not exact,
and every job aggregated behind it fails in turn.

Seven lines of `src/verifier/standard/META_TIERS.md` reached a blob that way.
The working copy on Windows ended those lines with two carriage returns before
the line feed. Git's clean filter strips the carriage return that immediately
precedes the line feed and leaves the one before it, so a doubled carriage
return on disk becomes a single CRLF in the blob, survives the normalization
that was supposed to remove it, and reproduces itself on every later `git add`.
Rewriting the file with line feeds only was what cleared it.

These tests close both ends: the committed blob a fresh checkout would rewrite,
and the byte sequence on disk that smuggles a carriage return into one.
"""

from __future__ import annotations

import functools
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
CARRIAGE_RETURN = b"\r"
DOUBLED_CARRIAGE_RETURN = b"\r\r\n"
GITLINK_MODE = b"160000"


def _git(root: Path, *arguments: str, stdin: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        input=stdin,
        check=True,
        capture_output=True,
        timeout=120,
    )
    return result.stdout


def _index_entries(root: Path) -> tuple[tuple[str, str], ...]:
    """Return every tracked path with the object name the index holds for it.

    One call, not one per file. The scan covers the whole tree, and a
    subprocess per path would cost more than every other test in this module.
    """

    entries: list[tuple[str, str]] = []
    for record in _git(root, "ls-files", "-s", "-z").split(b"\0"):
        if not record:
            continue
        metadata, _, path = record.partition(b"\t")
        mode, object_name, _stage = metadata.split(b" ")
        if mode == GITLINK_MODE:
            continue
        entries.append((path.decode("utf-8"), object_name.decode("ascii")))
    return tuple(entries)


def _declared(root: Path, paths: tuple[str, ...]) -> dict[str, dict[str, str]]:
    """Return the `text` and `eol` attributes `.gitattributes` gives each path."""

    stdin = b"".join(path.encode("utf-8") + b"\0" for path in paths)
    fields = _git(root, "check-attr", "--stdin", "-z", "text", "eol", stdin=stdin).split(b"\0")
    attributes: dict[str, dict[str, str]] = {}
    for start in range(0, len(fields) - 2, 3):
        path, attribute, value = (field.decode("utf-8") for field in fields[start:start + 3])
        attributes.setdefault(path, {})[attribute] = value
    return attributes


def _committed_bytes(root: Path, entries: tuple[tuple[str, str], ...]) -> dict[str, bytes]:
    """Read every committed blob through a single `git cat-file` stream.

    A shell line count is the wrong instrument here and reports the wrong
    number. The bytes have to be compared as bytes, never as decoded lines.
    """

    stdin = "".join(f"{object_name}\n" for _path, object_name in entries).encode("ascii")
    stream = _git(root, "cat-file", "--batch", stdin=stdin)
    contents: dict[str, bytes] = {}
    offset = 0
    for path, object_name in entries:
        end_of_header = stream.index(b"\n", offset)
        header = stream[offset:end_of_header].split(b" ")
        assert len(header) == 3 and header[0] == object_name.encode("ascii"), (
            f"git cat-file did not answer for {path} in the order it was asked"
        )
        start = end_of_header + 1
        size = int(header[2])
        contents[path] = stream[start:start + size]
        offset = start + size + 1
    return contents


def _holds_a_lone_carriage_return(content: bytes) -> bool:
    start = content.find(CARRIAGE_RETURN)
    while start != -1:
        if content[start + 1:start + 2] != b"\n":
            return True
        start = content.find(CARRIAGE_RETURN, start + 2)
    return False


def normalizes_to_lf(declared: dict[str, str], content: bytes) -> bool:
    """Report whether git rewrites this content on its way into a blob.

    `git check-attr` answers what `.gitattributes` declares; whether git acts
    on the declaration also depends on the bytes. `text` unset is the `binary`
    macro and is never converted. `text=auto` defers to git's own content test:
    content holding a null byte, or a carriage return that is not followed by a
    line feed, is treated as binary and passed through untouched, so its
    carriage returns survive the round trip and the checkout stays exact. That
    is why the committed portable network graphic and the monograph are not
    failures here. Only an explicit `text` converts unconditionally.
    """

    if declared.get("eol") != "lf":
        return False
    text = declared.get("text")
    if text == "set":
        return True
    if text == "auto":
        return b"\0" not in content and not _holds_a_lone_carriage_return(content)
    # `unset` is the binary macro. `unspecified` leaves the decision to local
    # configuration, which this repository cannot assert anything about.
    return False


@functools.lru_cache(maxsize=None)
def _lf_text(root: Path) -> tuple[tuple[str, bytes], ...]:
    """Return every tracked file git normalizes to LF, with its committed bytes."""

    entries = _index_entries(root)
    declared = _declared(root, tuple(path for path, _object_name in entries))
    contents = _committed_bytes(root, entries)
    return tuple(
        (path, contents[path])
        for path, _object_name in entries
        if normalizes_to_lf(declared.get(path, {}), contents[path])
    )


def rewritten_on_checkout(root: Path) -> dict[str, int]:
    """Return each committed blob that contradicts its own `eol=lf` declaration."""

    return {
        path: content.count(CARRIAGE_RETURN)
        for path, content in _lf_text(root)
        if CARRIAGE_RETURN in content
    }


def test_no_committed_blob_carries_a_carriage_return_under_eol_lf() -> None:
    offenders = rewritten_on_checkout(ROOT)
    assert not offenders, (
        "these committed blobs carry a carriage return although .gitattributes "
        f"declares them eol=lf: {offenders}. A fresh detached checkout writes "
        "those bytes to disk unchanged, git's own normalization reads them back "
        "as line feeds, and git status reports the file modified before anything "
        "has run, which is what the hosted presentation job refuses to build "
        "against. Rewrite the working copy with line feeds only and stage it "
        "again; editing the file in place is not enough if the editor keeps the "
        "carriage returns."
    )


def test_no_tracked_working_copy_carries_a_doubled_carriage_return() -> None:
    """Catch the shape on disk, which is what smuggles a carriage return in.

    A working copy holding plain CRLF is ordinary on Windows and normalizes
    away cleanly, so it is not an error. A doubled carriage return is the one
    shape that does not: the clean filter removes a single carriage return and
    leaves a valid CRLF behind in the blob. A file in this state is already
    staged wrong every time it is added, whatever the blob looks like today.
    """

    offenders = sorted(
        path
        for path, _content in _lf_text(ROOT)
        if (ROOT / path).is_file()
        and DOUBLED_CARRIAGE_RETURN in (ROOT / path).read_bytes()
    )
    assert not offenders, (
        f"these tracked files hold a doubled carriage return on disk: {offenders}. "
        "Staging them strips one carriage return and commits the other, so the "
        "committed tree is dirty the moment it is checked out. Rewrite each file "
        "with line feeds only."
    )


def _fixture_repository(root: Path) -> str:
    """Build a throwaway repository whose committed tree is dirty on checkout."""

    root.mkdir(parents=True, exist_ok=True)
    (root / ".gitattributes").write_bytes(b"* text eol=lf\n")
    (root / "clean.md").write_bytes(b"settled\n")
    _git(root, "init", "--quiet", ".")
    # Spelled in pieces because scripts/check_presentation.py scans this file
    # for address shapes, and finding one here is exactly its job.
    _git(root, "config", "user.email", "fixture" + "@" + "example.invalid")
    _git(root, "config", "user.name", "VSTD Test")
    _git(root, "add", ".gitattributes", "clean.md")
    # --no-filters is the only way to reproduce the defect, because it writes
    # the carriage returns straight into the blob, exactly as a doubled
    # carriage return on disk does through the clean filter.
    object_name = _git(
        root, "hash-object", "-w", "--no-filters", "--stdin", stdin=b"one\r\ntwo\r\n",
    ).decode("ascii").strip()
    _git(root, "update-index", "--add", "--cacheinfo", f"100644,{object_name},smuggled.md")
    _git(root, "commit", "--quiet", "-m", "fixture")
    return _git(root, "rev-parse", "HEAD").decode("ascii").strip()


def test_the_scan_names_exactly_what_a_fresh_checkout_reports_modified(tmp_path: Path) -> None:
    """A check that cannot fail says nothing about the tree it scans.

    The verdict is not asserted against a second copy of the same rule. It is
    asserted against `git status` in a real detached checkout, which is the
    thing the hosted job reads.
    """

    source = tmp_path / "source"
    commit = _fixture_repository(source)
    checkout = tmp_path / "checkout"
    _git(source, "worktree", "add", "--detach", "--quiet", str(checkout), commit)

    status = _git(checkout, "status", "--porcelain=v1", "--untracked-files=normal")
    reported = sorted(line[3:] for line in status.decode("utf-8").splitlines() if line)

    assert reported == ["smuggled.md"]
    assert sorted(rewritten_on_checkout(source)) == reported
    assert dict(_lf_text(source))["clean.md"] == b"settled\n"


def test_the_scan_leaves_content_git_treats_as_binary_alone() -> None:
    """Declared `text=auto` is a question about the bytes, not just the path.

    Narrowing this to the attribute alone would fail on the committed portable
    network graphic and the monograph, whose carriage returns git never
    converts and whose checkouts are therefore already exact.
    """

    explicit = {"text": "set", "eol": "lf"}
    assert normalizes_to_lf(explicit, b"one\ntwo\n")
    assert normalizes_to_lf(explicit, b"one\r\ntwo\n")

    automatic = {"text": "auto", "eol": "lf"}
    assert normalizes_to_lf(automatic, b"one\r\ntwo\n")
    assert not normalizes_to_lf(automatic, b"one\r\ntwo\n\x00")
    assert not normalizes_to_lf(automatic, b"one\rtwo\r\n")

    assert not normalizes_to_lf({"text": "unset", "eol": "lf"}, b"one\r\ntwo\n")
    assert not normalizes_to_lf({"text": "unspecified", "eol": "unspecified"}, b"one\r\n")
