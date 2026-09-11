"""Terminology: application programming interface (API); Hypertext Markup Language (HTML);
JavaScript Object Notation (JSON); uniform resource locator (URL);
Unicode Transformation Format, 8-bit (UTF-8); Verifier Standard (VSTD).

Validate assembled navigation, release boundaries and source-preserving presentation.
"""

from __future__ import annotations

import importlib.util
import json
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("docs_portal_test", ROOT / "scripts/build_docs_portal.py")
assert SPEC and SPEC.loader
PORTAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PORTAL)


class Page(HTMLParser):
    def __init__(self, content: str) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.links: list[str] = []
        self.canonical: str | None = None
        self.feed(content)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(str(values["id"]))
        if tag == "a" and values.get("href"):
            self.links.append(str(values["href"]))
        if tag in {"img", "script"} and values.get("src"):
            self.links.append(str(values["src"]))
        if tag == "link" and values.get("href"):
            if values.get("rel") == "canonical":
                self.canonical = values["href"]
            else:
                self.links.append(str(values["href"]))


@pytest.fixture(scope="module")
def site(tmp_path_factory: pytest.TempPathFactory) -> Path:
    output = tmp_path_factory.mktemp("portal") / "site"
    PORTAL.build(output)
    return output


def test_assembled_links_assets_and_anchors_resolve(site: Path) -> None:
    parsed = {path.resolve(): Page(path.read_text(encoding="utf-8")) for path in site.rglob("*.html")}
    errors = []
    for path, page in parsed.items():
        name = path.relative_to(site)
        if len(page.ids) != len(set(page.ids)):
            errors.append(f"{name}: duplicate anchors")
        assert page.canonical and page.canonical.startswith(PORTAL.SITE)
        for raw in page.links:
            link = urlsplit(raw)
            if link.scheme or link.netloc:
                continue
            target = (path.parent / unquote(link.path)).resolve() if link.path else path
            if target.is_dir():
                target /= "index.html"
            if not target.is_relative_to(site) or not target.is_file():
                errors.append(f"{name}: missing {raw}")
            elif link.fragment and target.suffix == ".html" and unquote(link.fragment) not in parsed[target].ids:
                errors.append(f"{name}: missing anchor {raw}")
    assert not errors, "\n".join(errors)


def test_release_and_repository_commands_remain_distinct(site: Path) -> None:
    current = (site / "reference.html").read_text(encoding="utf-8")
    released = (site / PORTAL.RELEASE_PATH / "reference.html").read_text(encoding="utf-8")
    assert 'id="cli-vstd-components-index"' in current
    assert 'id="cli-vstd-components-index"' not in released
    assert "UNRELEASED SOURCE" in current
    assert "RELEASED SOURCE" in released and "UNRELEASED SOURCE" not in released
    coordinate = json.loads((site / "portal-coordinate.json").read_text(encoding="utf-8"))
    assert coordinate["release_version"] == "1.3.0"
    assert coordinate["release_commit"] in released
    assert PORTAL.REPOSITORY + "/blob/main/" not in released
    for prefix in ("", PORTAL.RELEASE_PATH):
        page_coordinate = json.loads((site / prefix / "documentation-coordinate.json").read_text(encoding="utf-8"))
        assert page_coordinate["canonical_base_url"] == PORTAL.SITE + prefix


def test_search_results_bind_to_real_sections_and_correct_edition(site: Path) -> None:
    entries = json.loads((site / "search-index.json").read_text(encoding="utf-8"))
    pages = {path.relative_to(site).as_posix(): Page(path.read_text(encoding="utf-8")) for path in site.rglob("*.html")}
    for entry in entries:
        route, _, anchor = entry["url"].partition("#")
        assert route in pages
        if anchor:
            assert anchor in pages[route].ids
        assert entry["edition"] == ("release" if route.startswith(PORTAL.RELEASE_PATH) else "repository")
    assert any(item["title"] == "compute_canonical_digest function" for item in entries)
    assert any("Your first receipt" in item["title"] for item in entries)


def test_schema_bytes_and_existing_identifier_origin_are_preserved(site: Path) -> None:
    for folder in (ROOT / "receipts/schema", ROOT / "standard/schemas"):
        for source in folder.glob("*.json"):
            assert (site / "schemas" / source.name).read_bytes() == source.read_bytes()
            payload = json.loads(source.read_text(encoding="utf-8"))
            assert payload["$id"].startswith(PORTAL.OLD_SITE + "schemas/")


def test_presentation_preserves_math_lists_and_existing_anchors() -> None:
    original = '<main><aside>Old navigation</aside><article><h1>Guide</h1><h2 id="exact">Exact</h2><ol start="4"><li>Four<ul><li>Nested</li></ul></li></ol><p><code>x &lt; y</code></p><h2>Exact</h2><h2>Exact</h2></article></main>'
    content, title, outline = PORTAL.prepare_content(original)
    assert title == "Guide"
    assert '<ol start="4"><li>Four<ul><li>Nested</li></ul></li></ol>' in content
    assert '<code>x &lt; y</code>' in content
    assert outline == [("exact", "Exact"), ("exact-2", "Exact"), ("exact-3", "Exact")]
    assert "Old navigation" not in content
    legacy, _, _ = PORTAL.prepare_content('<main><h1>Demo</h1><h2 id="3060-second-demonstration">30–60 second demonstration</h2><a href="#30-60-second-demonstration">Demo</a></main>')
    assert set(Page(legacy).ids) == {"3060-second-demonstration", "30-60-second-demonstration"}


def test_portal_rejects_unsafe_output_and_non_origin_base(tmp_path: Path) -> None:
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    sentinel = occupied / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    with pytest.raises(ValueError, match="new or empty"):
        PORTAL.build(occupied)
    assert sentinel.read_text(encoding="utf-8") == "keep"
    with pytest.raises(ValueError, match="https origin"):
        PORTAL.build(tmp_path / "unused", base_url="https://example.com/subpath/")
    with pytest.raises(ValueError, match="under build"):
        PORTAL.build(ROOT / "docs" / "accidental-output")


def test_release_tag_must_match_pinned_commit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(PORTAL, "run", lambda *args, **kwargs: "0" * 40)
    with pytest.raises(ValueError, match="pinned documentation commit"):
        PORTAL.export_release(tmp_path / "changed-release")
    assert not (tmp_path / "changed-release").exists()
