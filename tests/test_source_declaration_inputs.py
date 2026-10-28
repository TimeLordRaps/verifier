"""The declaration inputs of one Python source: what polish may rebind without review.

Terminology: abstract syntax tree (AST).

A reviewed answer stays valid while nothing that namespace derivation reads from the
file changes.  Derivation reads definitions, lexical role hints, ``__vstd_kinds__``
markers, exports, imports as written, and the dynamic-construction flag.  It does not
read function bodies beyond those signals, so an edit that adds none of them leaves
the fingerprint equal even though the whole-file AST changed.  Anything that may add
an obligation must change the fingerprint; the fingerprint must never be the AST.
"""

from __future__ import annotations

import ast

import pytest

from verifier.runtime import source_declaration_inputs as inputs

BASE = '''\
import json


def total(items):
    result = 0
    for item in items:
        result += item
    return result
'''


def digest(source: str, path: str = "pkg/mod.py") -> str:
    return inputs.python_declaration_inputs_digest(path, source.encode("utf-8"))


def test_body_edit_that_adds_no_signal_keeps_inputs_though_the_ast_changes() -> None:
    edited = BASE.replace("result += item", "result = result + item * 1")
    assert ast.dump(ast.parse(BASE)) != ast.dump(ast.parse(edited))
    assert digest(edited) == digest(BASE)


def test_comments_docstrings_blank_lines_and_line_moves_keep_inputs() -> None:
    edited = '"""Module text."""\n\n# note\n\n\n' + BASE.replace(
        "def total(items):", "def total(items):\n    '''Sum the items.'''")
    assert digest(edited) == digest(BASE)


def test_renaming_a_local_without_a_role_word_keeps_inputs() -> None:
    assert digest(BASE.replace("result", "acc")) == digest(BASE)


@pytest.mark.parametrize("edit", [
    pytest.param(lambda s: s.replace("result", "robot_result"), id="role-word-in-a-name"),
    pytest.param(lambda s: s + "\n\ndef extra():\n    return 1\n", id="new-definition"),
    pytest.param(lambda s: s.replace("def total", "def sum_total"), id="renamed-definition"),
    pytest.param(lambda s: s.replace("import json", "import json\nimport socket"), id="new-import"),
    pytest.param(lambda s: s.replace("import json", "from os import path as json"), id="changed-import"),
    pytest.param(lambda s: s + '\n__vstd_kinds__ = ("LEDGER",)\n', id="kind-marker"),
    pytest.param(lambda s: s + '\n__all__ = ["total"]\n', id="export-list"),
    pytest.param(lambda s: s.replace("return result", "exec('x')\n    return result"),
                 id="dynamic-construction"),
])
def test_anything_that_can_add_an_obligation_changes_inputs(edit) -> None:
    assert digest(edit(BASE)) != digest(BASE)


def test_inputs_depend_on_the_path_because_surface_ids_name_it() -> None:
    assert digest(BASE, "pkg/a.py") != digest(BASE, "pkg/b.py")


def test_unparseable_source_has_no_inputs_and_is_never_treated_as_unchanged() -> None:
    with pytest.raises(ValueError, match="PYTHON_DECLARATION_INPUTS_UNAVAILABLE"):
        digest("def broken(:\n")
