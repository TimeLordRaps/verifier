"""Terminology: Python Enhancement Proposal (PEP).

The package declares support for Python 3.10 and later, but a developer running 3.12 or later
cannot see 3.10-incompatible source: PEP 701 let an f-string replacement field span lines, reuse
the enclosing quote, hold a comment and hold a backslash, and every newer interpreter accepts
that without complaint. This test parses every shipped, script and test source with the 3.10
grammar and, on interpreters that tokenize f-strings, rejects those four constructions directly."""

from __future__ import annotations

import ast
import io
import sys
import tokenize
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRECTORIES = ("src", "scripts", "tests")
FLOOR = (3, 10)
NEWER_TOKENS = sys.version_info >= (3, 12)


def newer_f_string_syntax(source: str) -> list[tuple[int, str]]:
    """Return (line, reason) for f-string syntax that Python 3.10 through 3.11 reject.

    Only interpreters from 3.12 tokenize an f-string into start, middle and end tokens; older
    interpreters reject the same constructions when the source is compiled, so they return no
    findings here.
    """
    if not NEWER_TOKENS:
        return []
    findings: list[tuple[int, str]] = []
    frames: list[list] = []  # one [delimiter, is_triple, brace_depth] per open f-string
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        kind, text, line = token.type, token.string, token.start[0]
        if kind == tokenize.FSTRING_END:
            frames.pop()
            continue
        open_fields = [frame for frame in frames if frame[2] > 0]
        for delimiter, triple, _ in open_fields:
            if kind in (tokenize.STRING, tokenize.FSTRING_START) and delimiter in text:
                findings.append((line, f"reuses the enclosing {delimiter} quote inside a replacement field"))
            if kind == tokenize.STRING and chr(92) in text:
                findings.append((line, "holds a backslash inside a replacement field"))
            if kind in (tokenize.NL, tokenize.NEWLINE) and not triple:
                findings.append((line, "breaks a line inside a replacement field of a single-quoted f-string"))
            if kind == tokenize.COMMENT:
                findings.append((line, "holds a comment inside a replacement field"))
        if kind == tokenize.FSTRING_START:
            delimiter = text.lstrip("rRfFbBuU")
            frames.append([delimiter, len(delimiter) == 3, 0])
        elif kind == tokenize.OP and frames:
            if text == "{":
                frames[-1][2] += 1
            elif text == "}":
                frames[-1][2] -= 1
    return sorted(set(findings))


def python_sources() -> list[Path]:
    paths: list[Path] = []
    for directory in SOURCE_DIRECTORIES:
        paths.extend(sorted((ROOT / directory).rglob("*.py")))
    return paths


def test_every_source_is_valid_under_the_python_3_10_grammar() -> None:
    sources = python_sources()
    assert sources, "no Python sources were found to check"
    failures: list[str] = []
    for path in sources:
        text = path.read_text(encoding="utf-8")
        name = path.relative_to(ROOT).as_posix()
        try:
            ast.parse(text, filename=name, feature_version=FLOOR)
        except SyntaxError as error:
            failures.append(f"{name}:{error.lineno}: {error.msg}")
            continue
        failures.extend(f"{name}:{line}: {reason}" for line, reason in newer_f_string_syntax(text))
    assert not failures, "\n".join(failures)


BACKSLASH = chr(92)

NEWER_ONLY = {
    "line break in a field": 'value = f"{row[(\n    "key"\n)]} tail"\n'.replace('"key"', "'key'"),
    "enclosing quote reused": 'value = f"{mapping["key"]}"\n',
    "enclosing single quote reused": "value = f'{mapping['key']}'\n",
    "backslash in a field": 'value = f"{' + "'" + BACKSLASH + "n'.join(parts)}" + '"\n',
    "comment in a field": 'value = f"{item  # why\n}"\n',
}

CLEAN = {
    "plain fields": 'value = f"{a} {b!r:>10} {{literal}}"\n',
    "other quote inside": 'value = f"{mapping[' + "'key'" + ']}"\n',
    "nested format spec": 'value = f"{number:{width}d}"\n',
    "dictionary display in a field": 'value = f"{ {' + "'a': 1}['a']" + ' }"\n',
    "triple quoted field over lines": 'value = f"""{first\n+ second}"""\n',
    "nested f-string with another quote": 'value = f"{f' + "'{inner}'" + '}"\n',
    "plain strings": 'value = "a" ' + "'b'" + "\n",
}


@pytest.mark.parametrize("name", sorted(NEWER_ONLY))
def test_newer_only_f_string_syntax_is_refused(name: str) -> None:
    source = NEWER_ONLY[name]
    if NEWER_TOKENS:
        assert newer_f_string_syntax(source), name
    else:
        with pytest.raises(SyntaxError):
            compile(source, name, "exec")


@pytest.mark.parametrize("name", sorted(CLEAN))
def test_f_strings_valid_on_the_floor_are_not_refused(name: str) -> None:
    source = CLEAN[name]
    compile(source, name, "exec")
    ast.parse(source, filename=name, feature_version=FLOOR)
    assert newer_f_string_syntax(source) == [], name
