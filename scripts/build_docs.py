#!/usr/bin/env python3
"""Terminology: Hypertext Markup Language (HTML); uniform resource locator (URL);
Verifier Standard (VSTD).

Render repository Markdown into the navigable GitHub Pages documentation site.

The repository Markdown remains authoritative.  This builder changes presentation and
links only; it does not maintain a second hand-edited copy of any specification or guide.
"""

from __future__ import annotations

from dataclasses import dataclass
import html
import os
from pathlib import Path, PurePosixPath
import re
from typing import Iterable, Mapping
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
CANONICAL_BASE = "https://timelordraps.github.io/verifier/"
SOURCE_REPOSITORY = "https://github.com/TimeLordRaps/verifier"


@dataclass(frozen=True)
class Document:
    source: Path
    route: PurePosixPath
    group: str
    title: str


@dataclass(frozen=True)
class OrientationDefinition:
    concept: str
    definition: str


ORIENTATION_LINK = re.compile(
    r'^\[([^]]+)\]\((https://en\.wikipedia\.org/wiki/[^)\s]+)\s+"Wikipedia orientation;[^"]+"\)$'
)


def _plain_markdown(value: str) -> str:
    value = re.sub(r"\[([^]]+)\]\([^)]+\)", r"\1", value)
    value = value.replace("`", "")
    value = re.sub(r"\*\*([^*]+)\*\*", r"\1", value)
    value = re.sub(r"~~([^~]+)~~", r"\1", value)
    return re.sub(r"\s+", " ", value).strip()


def orientation_definitions() -> dict[str, OrientationDefinition]:
    """Read the versioned hover-card definitions from the concepts glossary."""

    definitions: dict[str, OrientationDefinition] = {}
    source = ROOT / "docs/CONCEPTS_AND_PRECEDENTS.md"
    for line in source.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 3:
            continue
        match = ORIENTATION_LINK.fullmatch(cells[1])
        if not match:
            continue
        definitions.setdefault(
            match.group(2),
            OrientationDefinition(
                concept=_plain_markdown(cells[0]),
                definition=_plain_markdown(cells[2]),
            ),
        )

    # Two VSTD concepts deliberately use the same adjacent precedent. The popup
    # defines that shared precedent neutrally; each table row retains its own bound.
    definitions["https://en.wikipedia.org/wiki/Proof-carrying_code"] = (
        OrientationDefinition(
            concept="Proof-carrying code",
            definition=(
                "An untrusted producer supplies a result with a consumer-checkable "
                "certificate under a declared policy. VSTD treats this as an adjacent "
                "engineering precedent, not an inherited safety theorem."
            ),
        )
    )
    if not definitions:
        raise ValueError("orientation glossary contains no repository definitions")
    return definitions


def _first_heading(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^#\s+(.+?)\s*$", line)
        if match:
            return re.sub(r"[`*_]", "", match.group(1)).strip()
    return path.stem.replace("_", " ").replace("-", " ")


def _standard_sort(path: Path) -> tuple[int, int, str]:
    name = path.stem
    if name == "LADDER":
        return (0, 0, name)
    object_match = re.fullmatch(r"VSTD-(\d+)", name)
    if object_match:
        return (1, int(object_match.group(1)), name)
    graph_match = re.fullmatch(r"VSTD-Graph-(\d+)", name)
    if graph_match:
        return (2, int(graph_match.group(1)), name)
    if name == "ARTIFACT_CONTROL":
        return (3, 0, name)
    if name == "WIRE_IDENTIFIERS":
        return (4, 0, name)
    return (5, 0, name)


def documents() -> tuple[Document, ...]:
    """Return every Markdown source that is intentionally rendered on the site."""

    found: list[Document] = []
    standards = sorted((ROOT / "standard").glob("*.md"), key=_standard_sort)
    for source in standards:
        route = (
            PurePosixPath("standard/index.html")
            if source.name == "LADDER.md"
            else PurePosixPath("standard") / f"{source.stem}.html"
        )
        found.append(Document(source, route, "Normative specifications", _first_heading(source)))

    guides = sorted((ROOT / "docs").rglob("*.md"))
    for source in guides:
        relative = source.relative_to(ROOT).with_suffix(".html")
        group = "Guides and concepts"
        if "profiles" in relative.parts or "standards" in relative.parts:
            group = "Profiles and interoperability"
        found.append(
            Document(
                source,
                PurePosixPath(relative.as_posix()),
                group,
                _first_heading(source),
            )
        )

    experiments = sorted((ROOT / "experiments").rglob("*.md"))
    for source in experiments:
        relative = source.relative_to(ROOT).with_suffix(".html")
        if source.name == "INDEX.md":
            relative = Path("experiments/index.html")
        found.append(
            Document(
                source,
                PurePosixPath(relative.as_posix()),
                "Experiments",
                _first_heading(source),
            )
        )

    project_names = (
        "README.md",
        "ROADMAP.md",
        "GOVERNANCE.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "RELEASING.md",
        "CODE_OF_CONDUCT.md",
        "CHANGELOG.md",
        "HUMANS.md",
        "AGENTS.md",
        "TIME.md",
    )
    for name in project_names:
        source = ROOT / name
        if source.is_file():
            found.append(
                Document(
                    source,
                    PurePosixPath("project") / f"{source.stem}.html",
                    "Project and contribution",
                    _first_heading(source),
                )
            )
    return tuple(found)


def _slug(value: str) -> str:
    plain = re.sub(r"<[^>]*>", "", value)
    plain = re.sub(r"[`*_~]", "", plain).lower()
    plain = re.sub(r"[^a-z0-9\s-]", "", plain)
    return re.sub(r"[-\s]+", "-", plain).strip("-") or "section"


def _relative_link(source_route: PurePosixPath, target_route: PurePosixPath) -> str:
    return PurePosixPath(
        os.path.relpath(target_route.as_posix(), source_route.parent.as_posix()).replace("\\", "/")
    ).as_posix()


class MarkdownRenderer:
    """Small deterministic renderer for the Markdown constructs used in this repository."""

    FENCE = re.compile(r"^\s*(```+|~~~+)\s*([^\s`]*)\s*$")
    HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
    LIST_ITEM = re.compile(r"^(\s*)([-+*]|\d+[.)])\s+(.+)$")
    TABLE_RULE = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|?\s*$")
    HORIZONTAL_RULE = re.compile(r"^\s*(?:-{3,}|\*\s*\*\s*\*|_{3,})\s*$")
    INLINE_CODE = re.compile(r"`([^`]+)`")
    INLINE_MATH = re.compile(r"(?<!\\)\$([^$\n]+)\$")
    IMAGE = re.compile(r"!\[([^]]*)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
    LINK = re.compile(r"\[([^]]+)\]\(([^)\s]+)(?:\s+\"([^\"]*)\")?\)")

    def __init__(
        self,
        source: Path,
        route: PurePosixPath,
        route_map: dict[Path, PurePosixPath],
        source_ref: str,
        orientation_map: Mapping[str, OrientationDefinition],
    ) -> None:
        self.source = source.resolve()
        self.route = route
        self.route_map = route_map
        self.source_ref = "main" if source_ref == "WORKTREE" else source_ref
        self.orientation_map = orientation_map
        self.heading_counts: dict[str, int] = {}
        self.outline: list[tuple[int, str, str]] = []

    def _repository_link(self, relative: Path, *, directory: bool) -> str:
        operation = "tree" if directory else "blob"
        ref = quote(self.source_ref, safe="")
        encoded = "/".join(quote(part) for part in relative.parts)
        return f"{SOURCE_REPOSITORY}/{operation}/{ref}/{encoded}"

    def _target(self, raw: str, *, image: bool = False) -> str:
        repository_relative = False
        repository_prefix = f"{SOURCE_REPOSITORY}/blob/main/"
        if raw.startswith(repository_prefix):
            raw = raw.removeprefix(repository_prefix)
            repository_relative = True
        if raw.startswith(("#", "http://", "https://", "mailto:", "data:")):
            return raw
        target_text, separator, fragment = raw.partition("#")
        base = ROOT if repository_relative else self.source.parent
        resolved = (base / target_text).resolve()
        if resolved in self.route_map:
            rewritten = _relative_link(self.route, self.route_map[resolved])
        else:
            try:
                relative = resolved.relative_to(ROOT)
            except ValueError:
                return raw
            parts = relative.parts
            if parts == ("docs", "reference.html"):
                rewritten = _relative_link(self.route, PurePosixPath("reference.html"))
            elif parts[:2] == ("docs", "assets"):
                asset_route = PurePosixPath(*parts[1:])
                rewritten = _relative_link(self.route, asset_route)
            elif (
                parts[:2] in {("receipts", "schema"), ("standard", "schemas")}
                and resolved.is_file()
            ):
                rewritten = _relative_link(
                    self.route, PurePosixPath("schemas") / relative.name
                )
            else:
                rewritten = self._repository_link(relative, directory=resolved.is_dir())
        if separator and fragment:
            rewritten += "#" + quote(fragment, safe="-._~")
        return rewritten

    def inline(self, value: str) -> str:
        tokens: list[str] = []

        def token(rendered: str) -> str:
            marker = f"\x00{len(tokens)}\x00"
            tokens.append(rendered)
            return marker

        def render_link(match: re.Match[str]) -> str:
            target = self._target(match.group(2))
            title = match.group(3)
            orientation = self.orientation_map.get(match.group(2))
            attributes = [f'href="{html.escape(target, quote=True)}"']
            if orientation and title and title.startswith("Wikipedia orientation"):
                attributes.extend(
                    (
                        'class="orientation-link"',
                        'data-orientation-preview="repository"',
                        f'data-orientation-concept="{html.escape(orientation.concept, quote=True)}"',
                        f'data-orientation-definition="{html.escape(orientation.definition, quote=True)}"',
                        f'data-orientation-boundary="{html.escape(title, quote=True)}"',
                        'rel="noreferrer"',
                    )
                )
            elif title:
                attributes.append(f'title="{html.escape(title, quote=True)}"')
            return f'<a {" ".join(attributes)}>{self.inline(match.group(1))}</a>'

        value = self.INLINE_CODE.sub(
            lambda match: token(f"<code>{html.escape(match.group(1))}</code>"), value
        )
        value = self.INLINE_MATH.sub(
            lambda match: token(
                f'<span class="math" aria-label="mathematical expression">'
                f"{html.escape(match.group(1))}</span>"
            ),
            value,
        )
        value = self.IMAGE.sub(
            lambda match: token(
                f'<img src="{html.escape(self._target(match.group(2), image=True), quote=True)}" '
                f'alt="{html.escape(match.group(1), quote=True)}">'
            ),
            value,
        )
        value = self.LINK.sub(
            lambda match: token(render_link(match)),
            value,
        )
        value = html.escape(value, quote=False)
        value = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", value)
        value = re.sub(r"__([^_]+)__", r"<strong>\1</strong>", value)
        value = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", value)
        value = re.sub(r"(?<!_)_([^_]+)_(?!_)", r"<em>\1</em>", value)
        value = re.sub(r"~~([^~]+)~~", r"<del>\1</del>", value)
        value = re.sub(
            r"&lt;(https?://[^&]+)&gt;",
            lambda match: f'<a href="{match.group(1)}">{match.group(1)}</a>',
            value,
        )
        for index in reversed(range(len(tokens))):
            value = value.replace(f"\x00{index}\x00", tokens[index])
        return value

    @staticmethod
    def _table_cells(line: str) -> list[str]:
        stripped = line.strip().strip("|")
        cells = re.split(r"(?<!\\)\|", stripped)
        return [cell.strip().replace("\\|", "|") for cell in cells]

    def _render_table(self, lines: list[str], index: int) -> tuple[str, int]:
        headings = self._table_cells(lines[index])
        index += 2
        rows: list[list[str]] = []
        while index < len(lines) and "|" in lines[index] and lines[index].strip():
            rows.append(self._table_cells(lines[index]))
            index += 1
        head = "".join(f"<th>{self.inline(cell)}</th>" for cell in headings)
        body = ""
        for row in rows:
            padded = row + [""] * max(0, len(headings) - len(row))
            body += "<tr>" + "".join(
                f"<td>{self.inline(cell)}</td>" for cell in padded[: len(headings)]
            ) + "</tr>\n"
        return (
            '<div class="doc-table"><table><thead><tr>'
            + head
            + "</tr></thead><tbody>\n"
            + body
            + "</tbody></table></div>",
            index,
        )

    def _render_list(self, lines: list[str], index: int) -> tuple[str, int]:
        first = self.LIST_ITEM.match(lines[index])
        assert first is not None
        base_indent = len(first.group(1).replace("\t", "    "))
        ordered = first.group(2)[0].isdigit()
        tag = "ol" if ordered else "ul"
        items: list[str] = []
        while index < len(lines):
            match = self.LIST_ITEM.match(lines[index])
            if match is None:
                break
            indent = len(match.group(1).replace("\t", "    "))
            is_ordered = match.group(2)[0].isdigit()
            if indent != base_indent or is_ordered != ordered:
                break
            parts = [match.group(3).strip()]
            nested: list[str] = []
            index += 1
            while index < len(lines):
                next_match = self.LIST_ITEM.match(lines[index])
                if next_match:
                    next_indent = len(next_match.group(1).replace("\t", "    "))
                    next_ordered = next_match.group(2)[0].isdigit()
                    if next_indent == base_indent and next_ordered == ordered:
                        break
                    if next_indent <= base_indent:
                        break
                    child, index = self._render_list(lines, index)
                    nested.append(child)
                    continue
                if lines[index].strip() and (
                    len(lines[index]) - len(lines[index].lstrip()) > base_indent
                ):
                    parts.append(lines[index].strip())
                    index += 1
                    continue
                break
            items.append(self.inline(" ".join(parts)) + "".join(nested))
        return (
            f"<{tag}>" + "".join(f"<li>{item}</li>" for item in items) + f"</{tag}>",
            index,
        )

    def render(self, markdown: str) -> str:
        lines = markdown.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        output: list[str] = []
        paragraph: list[str] = []

        def flush_paragraph() -> None:
            if paragraph:
                joined = " ".join(part.strip() for part in paragraph)
                output.append(f"<p>{self.inline(joined)}</p>")
                paragraph.clear()

        index = 0
        while index < len(lines):
            line = lines[index]
            display_math = re.match(r"^\s*\$\$(.+)\$\$\s*$", line)
            if display_math:
                flush_paragraph()
                output.append(
                    '<div class="math-block" aria-label="mathematical expression">'
                    + html.escape(display_math.group(1).strip())
                    + "</div>"
                )
                index += 1
                continue
            fence = self.FENCE.match(line)
            if fence:
                flush_paragraph()
                marker, language = fence.groups()
                index += 1
                code: list[str] = []
                while index < len(lines) and not lines[index].lstrip().startswith(marker[:3]):
                    code.append(lines[index])
                    index += 1
                if index < len(lines):
                    index += 1
                language_class = (
                    f' class="language-{html.escape(language, quote=True)}"' if language else ""
                )
                output.append(
                    f"<pre><code{language_class}>{html.escape(chr(10).join(code))}</code></pre>"
                )
                continue
            heading = self.HEADING.match(line)
            if heading:
                flush_paragraph()
                level = len(heading.group(1))
                text = heading.group(2)
                anchor = _slug(text)
                count = self.heading_counts.get(anchor, 0)
                self.heading_counts[anchor] = count + 1
                if count:
                    anchor = f"{anchor}-{count}"
                output.append(
                    f'<h{level} id="{anchor}">{self.inline(text)}'
                    f'<a class="heading-anchor" href="#{anchor}" aria-label="Link to this section">#</a>'
                    f"</h{level}>"
                )
                self.outline.append((level, re.sub(r"[`*_~]", "", text), anchor))
                index += 1
                continue
            if (
                index + 1 < len(lines)
                and "|" in line
                and self.TABLE_RULE.match(lines[index + 1])
            ):
                flush_paragraph()
                table, index = self._render_table(lines, index)
                output.append(table)
                continue
            if self.LIST_ITEM.match(line):
                flush_paragraph()
                rendered_list, index = self._render_list(lines, index)
                output.append(rendered_list)
                continue
            if line.lstrip().startswith(">"):
                flush_paragraph()
                quote_lines: list[str] = []
                while index < len(lines) and lines[index].lstrip().startswith(">"):
                    quote_lines.append(re.sub(r"^\s*>\s?", "", lines[index]))
                    index += 1
                quoted = MarkdownRenderer(
                    self.source,
                    self.route,
                    self.route_map,
                    self.source_ref,
                    self.orientation_map,
                ).render("\n".join(quote_lines))
                output.append(f"<blockquote>{quoted}</blockquote>")
                continue
            if self.HORIZONTAL_RULE.match(line):
                flush_paragraph()
                output.append("<hr>")
                index += 1
                continue
            if line.startswith("    "):
                flush_paragraph()
                code = []
                while index < len(lines) and (lines[index].startswith("    ") or not lines[index]):
                    code.append(lines[index][4:] if lines[index].startswith("    ") else "")
                    index += 1
                output.append(f"<pre><code>{html.escape(chr(10).join(code).rstrip())}</code></pre>")
                continue
            if re.match(r"^\s*<img\s", line, re.IGNORECASE):
                flush_paragraph()
                src_match = re.search(r'\bsrc=["\']([^"\']+)["\']', line, re.IGNORECASE)
                alt_match = re.search(r'\balt=["\']([^"\']*)["\']', line, re.IGNORECASE)
                if src_match:
                    src = self._target(src_match.group(1), image=True)
                    alt = alt_match.group(1) if alt_match else ""
                    output.append(
                        f'<p class="doc-image"><img src="{html.escape(src, quote=True)}" '
                        f'alt="{html.escape(alt, quote=True)}"></p>'
                    )
                index += 1
                continue
            if re.match(r"^\s*</?div(?:\s[^>]*)?>\s*$", line, re.IGNORECASE):
                flush_paragraph()
                index += 1
                continue
            if not line.strip():
                flush_paragraph()
                index += 1
                continue
            paragraph.append(line)
            index += 1
        flush_paragraph()
        return "\n".join(output)


def _canonical(route: PurePosixPath) -> str:
    value = route.as_posix()
    if value.endswith("/index.html"):
        value = value[: -len("index.html")]
    return CANONICAL_BASE + value


def _top_navigation(route: PurePosixPath, *, current: str) -> str:
    prefix = _relative_link(route, PurePosixPath("index.html"))
    root = prefix.removesuffix("index.html")
    links = (
        ("Overview", root + "index.html", "overview"),
        ("Guides", root + "guides.html", "guides"),
        ("Reference", root + "reference.html", "reference"),
        ("Demo", "https://github.com/TimeLordRaps/verifier#30-60-second-demonstration", "demo"),
        ("Standard", root + "standard/", "standard"),
        ("Experiments", root + "experiments/", "experiments"),
        ("Project", root + "project/ROADMAP.html", "project"),
        ("GitHub", "https://github.com/TimeLordRaps/verifier", "github"),
    )
    rendered = []
    for label, target, key in links:
        marker = ' aria-current="page"' if key == current else ""
        rendered.append(f'<a href="{target}"{marker}>{label}</a>')
    return (
        '<header class="wrap"><nav aria-label="Primary">'
        f'<a class="brand" href="{root}index.html">VSTD</a>'
        f'<div class="links">{"".join(rendered)}</div></nav></header>'
    )


def _sidebar(
    current: Document,
    all_documents: Iterable[Document],
    outline: Iterable[tuple[int, str, str]],
) -> str:
    groups: dict[str, list[Document]] = {}
    for document in all_documents:
        groups.setdefault(document.group, []).append(document)
    sections: list[str] = []
    on_this_page = [entry for entry in outline if entry[0] in {2, 3}]
    if on_this_page:
        links = "".join(
            f'<li class="toc-depth-{level}"><a href="#{anchor}">{html.escape(title)}</a></li>'
            for level, title, anchor in on_this_page
        )
        sections.append(f'<section><h2>On this page</h2><ul>{links}</ul></section>')
    for group, entries in groups.items():
        links = []
        for document in entries:
            target = _relative_link(current.route, document.route)
            marker = ' aria-current="page"' if document.route == current.route else ""
            links.append(
                f'<li><a href="{target}"{marker}>{html.escape(document.title)}</a></li>'
            )
        sections.append(
            f'<section><h2>{html.escape(group)}</h2><ul>{"".join(links)}</ul></section>'
        )
    return (
        '<aside class="doc-sidebar" aria-label="Documentation sections" tabindex="0">'
        + "".join(sections)
        + "</aside>"
    )


def render_document(
    document: Document,
    all_documents: tuple[Document, ...],
    *,
    source_ref: str,
    orientation_map: Mapping[str, OrientationDefinition],
) -> str:
    route_map = {item.source.resolve(): item.route for item in all_documents}
    markdown = document.source.read_text(encoding="utf-8")
    renderer = MarkdownRenderer(
        document.source, document.route, route_map, source_ref, orientation_map
    )
    content = renderer.render(markdown)
    source_relative = document.source.relative_to(ROOT).as_posix()
    source_link = renderer._repository_link(Path(source_relative), directory=False)
    if document.group == "Normative specifications":
        current = "standard"
    elif document.group == "Experiments":
        current = "experiments"
    elif document.group == "Project and contribution":
        current = "project"
    else:
        current = "guides"
    if document.group == "Normative specifications":
        status = "Normative source"
    elif document.group == "Experiments":
        status = "Non-normative experiment record"
    else:
        status = "Maintained repository documentation"
    orientation_script = ""
    if 'data-orientation-preview="repository"' in content:
        script_source = _relative_link(
            document.route, PurePosixPath("assets/orientation-previews.js")
        )
        orientation_script = f'<script src="{script_source}" defer></script>'
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="{html.escape(document.title, quote=True)} — Verifier Standard documentation.">
  <meta property="og:title" content="{html.escape(document.title, quote=True)} — VSTD">
  <meta property="og:type" content="article">
  <meta property="og:url" content="{_canonical(document.route)}">
  <title>{html.escape(document.title)} &mdash; VSTD documentation</title>
  <link rel="canonical" href="{_canonical(document.route)}">
  <link rel="stylesheet" href="{_relative_link(document.route, PurePosixPath('assets/site.css'))}">
</head>
<body>
  <a class="skip-link" href="#document">Skip to documentation</a>
  {_top_navigation(document.route, current=current)}
  <main class="wrap doc-shell" id="document">
    {_sidebar(document, all_documents, renderer.outline)}
    <article class="doc-content">
      <div class="doc-coordinate"><span>{status}</span><a href="{source_link}">View source on GitHub</a></div>
      <p class="doc-boundary">Rendered from <code>{html.escape(source_relative)}</code> at build time without changing its status. The repository source controls if this presentation differs.</p>
      {content}
    </article>
  </main>
  <footer><div class="wrap">VSTD &middot; Apache-2.0 &middot; Maintainer-led alpha &middot; No standards-body endorsement claimed.</div></footer>
  {orientation_script}
</body>
</html>
"""


def build(output: Path, *, source_ref: str = "WORKTREE") -> tuple[Path, ...]:
    """Render the documentation into an existing Pages output directory."""

    output = output.resolve()
    if not output.is_dir():
        raise ValueError(f"documentation output directory does not exist: {output}")
    all_documents = documents()
    orientation_map = orientation_definitions()
    used_orientation_urls = {
        match.group(2)
        for document in all_documents
        for line in document.source.read_text(encoding="utf-8").splitlines()
        for match in MarkdownRenderer.LINK.finditer(line)
        if match.group(2).startswith("https://en.wikipedia.org/wiki/")
        and (match.group(3) or "").startswith("Wikipedia orientation")
    }
    missing = sorted(used_orientation_urls - orientation_map.keys())
    if missing:
        raise ValueError(
            "orientation links lack repository definitions: " + ", ".join(missing)
        )
    written: list[Path] = []
    targets = [output / Path(document.route.as_posix()) for document in all_documents]
    existing = [target for target in targets if target.exists()]
    if existing:
        names = ", ".join(target.relative_to(output).as_posix() for target in existing[:3])
        raise ValueError(f"refusing to overwrite generated documentation: {names}")
    for document, target in zip(all_documents, targets):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            render_document(
                document,
                all_documents,
                source_ref=source_ref,
                orientation_map=orientation_map,
            ),
            encoding="utf-8",
            newline="\n",
        )
        written.append(target)
    return tuple(written)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-ref", default="WORKTREE")
    args = parser.parse_args()
    written = build(args.output, source_ref=args.source_ref)
    print(f"[DOCS OK] rendered {len(written)} navigable pages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
