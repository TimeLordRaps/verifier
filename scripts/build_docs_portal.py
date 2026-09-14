#!/usr/bin/env python3
"""Terminology: application programming interface (API); command-line interface (CLI);
Hypertext Markup Language (HTML); JavaScript Object Notation (JSON);
Python Package Index (PyPI); uniform resource locator (URL);
Unicode Transformation Format, 8-bit (UTF-8); Verifier Standard (VSTD).

Build the documentation-domain presentation from maintained sources and a release tag.
The existing Pages assembler and its frozen schema identifiers remain authoritative.
"""

from __future__ import annotations

import argparse
import hashlib
import html
from html.parser import HTMLParser
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SITE = "https://verifier-standard.com/"
OLD_SITE = "https://timelordraps.github.io/verifier/"
REPOSITORY = "https://github.com/TimeLordRaps/verifier"
RELEASE = "1.3.0"
RELEASE_TAG = "v" + RELEASE
RELEASE_COMMIT = "adc0415ea653376ed3f4c146a84daac1f72913f6"
RELEASE_PATH = "releases/" + RELEASE + "/"
ASSETS = ROOT / "scripts" / "portal"


def run(arguments: list[str], *, cwd: Path = ROOT) -> str:
    return subprocess.run(arguments, cwd=cwd, check=True, capture_output=True,
                          text=True, encoding="utf-8", timeout=90).stdout.strip()


class Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def plain(markup: str) -> str:
    parser = Text()
    parser.feed(markup)
    return " ".join(" ".join(parser.parts).split())


def heading_text(markup: str) -> str:
    return plain(re.sub(r'<a\b[^>]*class="heading-anchor"[^>]*>.*?</a>', '', markup, flags=re.S))


def assemble(source: Path, output: Path, source_ref: str) -> None:
    print(f"[PORTAL] Assemble documentation at {source_ref}", flush=True)
    environment = dict(os.environ, PYTHONPATH=str(source / "src"))
    subprocess.run([sys.executable, "-u", "scripts/build_reference.py", "--check"],
                   cwd=source, env=environment, check=True, timeout=60)
    subprocess.run([sys.executable, "-u", "scripts/build_pages.py", "--output",
                    str(output), "--source-ref", source_ref], cwd=source,
                   env=environment, check=True, timeout=90)


def export_release(destination: Path) -> str:
    commit = run(["git", "rev-parse", RELEASE_TAG + "^{commit}"])
    if commit != RELEASE_COMMIT:
        raise ValueError("release tag does not match its pinned documentation commit")
    archive = subprocess.run(["git", "archive", "--format=zip", commit], cwd=ROOT,
                             capture_output=True, check=True, timeout=30).stdout
    destination.mkdir()
    with zipfile.ZipFile(io.BytesIO(archive)) as source:
        for member in source.infolist():
            target = (destination / member.filename).resolve()
            if not target.is_relative_to(destination.resolve()):
                raise ValueError("release archive contains a path outside its root")
        source.extractall(destination)
    project = (destination / "pyproject.toml").read_text(encoding="utf-8")
    if not re.search(r'^version\s*=\s*"' + re.escape(RELEASE) + r'"\s*$', project, re.M):
        raise ValueError("release tag and declared package version disagree")
    return commit


def prepare_content(page: str) -> tuple[str, str, list[tuple[str, str]]]:
    main = re.search(r"<main\b[^>]*>(.*?)</main>", page, re.S)
    if main is None:
        raise ValueError("page has no main content")
    content = re.sub(r'<aside\b[^>]*>.*?</aside>', '', main.group(1), flags=re.S)
    title_match = re.search(r"<h1\b[^>]*>(.*?)</h1>", content, re.S)
    title = heading_text(title_match.group(1)) if title_match else "Documentation"
    source_notes = re.findall(r'<div class="doc-coordinate">.*?</div>|<p class="doc-boundary">.*?</p>', content, re.S)
    content = re.sub(r'<div class="doc-coordinate">.*?</div>|<p class="doc-boundary">.*?</p>', '', content, flags=re.S)
    ids = set(re.findall(r'\bid="([^"]+)"', content))
    outline: list[tuple[str, str]] = []

    def heading(match: re.Match[str]) -> str:
        level, attrs, inner = match.groups()
        found = re.search(r'\bid="([^"]+)"', attrs)
        if found:
            anchor = found.group(1)
        else:
            base = re.sub(r"[^a-z0-9]+", "-", plain(inner).lower()).strip("-") or "section"
            anchor = base
            suffix = 2
            while anchor in ids:
                anchor = f"{base}-{suffix}"
                suffix += 1
            ids.add(anchor)
            attrs += f' id="{anchor}"'
        if level == "2":
            outline.append((anchor, heading_text(inner)))
        return f'<h{level}{attrs}>{inner}</h{level}>'

    content = re.sub(r'<h([23])\b([^>]*)>(.*?)</h\1>', heading, content, flags=re.S)
    # Published README links use a hyphen while the source renderer removes its
    # en dash. Retain both spellings without changing the release's source text.
    if 'id="3060-second-demonstration"' in content and 'id="30-60-second-demonstration"' not in content:
        content = content.replace('<h2 id="3060-second-demonstration">', '<span id="30-60-second-demonstration"></span><h2 id="3060-second-demonstration">')
    content += '<div class="source-notes">' + ''.join(source_notes) + '</div>' if source_notes else ''
    return content, title, outline


def navigation(prefix: str, output: Path) -> list[tuple[str, list[tuple[str, str]]]]:
    def route(path: str) -> str:
        return prefix + path if (output / (prefix + path)).exists() else path

    return [
        ("Start here", [("Introduction", prefix + "index.html"),
                         ("Install Verifier", "docs/INSTALLATION.html"),
                         ("Your first receipt", "docs/FIRST_RECEIPT.html")]),
        ("Understand the model", [("Concepts & precedents", route("docs/CONCEPTS_AND_PRECEDENTS.html")),
                                  ("Claims & limits", route("docs/CLAIMS_AND_LIMITS.html")),
                                  ("Numbered profiles", route("standard/index.html")),
                                  ("All guides", route("guides.html"))]),
        ("Package reference · " + RELEASE, [("Commands", RELEASE_PATH + "reference.html#cli"),
                                            ("Python exports", RELEASE_PATH + "reference.html#api"),
                                            ("Compatibility policy", RELEASE_PATH + "docs/API_STABILITY.html")]),
        ("Work in the repository", [("Repository walkthrough", "docs/REPOSITORY_WALKTHROUGH.html"),
                                    ("Current source reference", "reference.html"),
                                    ("Component catalog", "components/index.html"),
                                    ("Architecture", "docs/ARCHITECTURE.html"),
                                    ("Experiments", "experiments/index.html")]),
        ("Contribute", [("Contribution guidelines", "project/CONTRIBUTING.html"),
                        ("Security reporting", "project/SECURITY.html"),
                        ("Roadmap", "project/ROADMAP.html"),
                        ("Changelog", "project/CHANGELOG.html")]),
    ]


def home() -> str:
    return (ASSETS / "home.html.in").read_text(encoding="utf-8").replace("{{release}}", RELEASE).replace("{{release_path}}", RELEASE_PATH)


def shell(content: str, *, route: str, title: str, outline: list[tuple[str, str]],
          output: Path, base_url: str, source_ref: str) -> str:
    stable = route.startswith(RELEASE_PATH)
    prefix = RELEASE_PATH if stable else ""
    depth = len(Path(route).parts) - 1
    root = "../" * depth

    def link(path: str) -> str:
        return root + path

    def navlink(label: str, target: str) -> str:
        current = ' aria-current="page"' if route == target.split("#")[0] else ""
        return f'<a href="{link(target)}"{current}>{html.escape(label)}</a>'

    groups = navigation(prefix, output)
    sidebar = "".join(f'<section><h2>{html.escape(label)}</h2>' +
                      "".join(navlink(name, target) for name, target in entries) + "</section>"
                      for label, entries in groups)
    toc = "".join(f'<a href="#{anchor}">{html.escape(label)}</a>' for anchor, label in outline)
    coordinate = "Released package " + RELEASE if stable else "Repository documentation"
    other = route.removeprefix(RELEASE_PATH) if stable else RELEASE_PATH + route
    if not (output / other).is_file():
        other = "index.html" if stable else RELEASE_PATH + "index.html"
    version_links = navlink("Released " + RELEASE, route if stable else other) + navlink("Repository source", other if stable else route)
    source = REPOSITORY + "/tree/" + source_ref
    known = [target for _, entries in groups for _, target in entries if "#" not in target]
    next_link = ""
    if route in known and known.index(route) + 1 < len(known):
        target = known[known.index(route) + 1]
        label = next(name for _, entries in groups for name, path in entries if path == target)
        next_link = f'<a class="next-page" href="{link(target)}"><small>CONTINUE READING</small><span>{html.escape(label)} <b aria-hidden="true">→</b></span></a>'
    canonical = base_url + (route.removesuffix("index.html") if route.endswith("index.html") else route)
    stylesheet = 'assets/portal.css?v=' + hashlib.sha256((ASSETS / 'portal.css').read_bytes()).hexdigest()[:12]
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} · Verifier documentation</title>
<meta name="description" content="{html.escape(title, quote=True)} — Verifier Standard documentation, guides and implementation reference.">
<link rel="canonical" href="{canonical}"><meta property="og:title" content="{html.escape(title, quote=True)} · Verifier">
<meta property="og:url" content="{canonical}"><meta property="og:type" content="website">
<link rel="icon" href="{link('assets/portal-mark.svg')}" type="image/svg+xml">
<link rel="stylesheet" href="{link('assets/site.css')}"><link rel="stylesheet" href="{link(stylesheet)}">
<script src="{link('assets/portal.js')}" defer></script>
<script src="{link('assets/orientation-previews.js')}" defer></script></head>
<body class="portal" data-root="{root}" data-edition="{'release' if stable else 'repository'}">
<a class="skip-link" href="#document">Skip to documentation</a>
<header class="portal-header"><a class="portal-brand" href="{link('index.html')}"><img src="{link('assets/portal-mark.svg')}" width="28" height="28" alt=""><strong>Verifier</strong><span>docs</span></a>
<button class="search-trigger" type="button" aria-haspopup="dialog"><span aria-hidden="true">⌕</span> Search documentation <kbd>Ctrl K</kbd></button>
<nav aria-label="External resources"><a href="https://pypi.org/project/verifier-standard/">PyPI<span class="sr-only"> — Python Package Index</span></a><a href="{REPOSITORY}">GitHub ↗</a><a href="https://vstd-labs.com">VSTD Labs ↗</a></nav>
<button class="theme-toggle" aria-label="Switch color theme" type="button">◐</button><button class="menu-toggle" aria-expanded="false" aria-controls="portal-sidebar" type="button">Menu</button></header>
<div class="portal-layout"><aside id="portal-sidebar" class="portal-sidebar" aria-label="Documentation navigation">
<details class="version-picker"><summary><span class="version-dot"></span>{coordinate}<span aria-hidden="true">⌄</span></summary><div>{version_links}</div></details>
{sidebar}<div class="sidebar-foot">Verifier Standard (VSTD)<br>Open source · Apache-2.0</div></aside>
<main id="document" class="portal-main"><span id="top"></span><div class="page-context"><a href="{link('index.html')}">Documentation</a><span>/</span><span>{html.escape(title)}</span></div>
<div class="edition-note {'stable' if stable else ''}"><span class="version-dot"></span><strong>{coordinate}</strong><span>{'Source pinned to ' + RELEASE_TAG if stable else 'May include additions beyond the released package'}</span></div>
<div class="portal-content">{content}</div>{next_link}
<footer class="portal-footer"><span>Maintainer-led alpha · No standards-body endorsement claimed.</span><a href="{source}">Source coordinate ↗</a></footer></main>
<aside class="portal-toc" aria-label="On this page"><p>On this page</p>{toc}<div class="toc-extra"><a href="{REPOSITORY}/issues/new/choose">Improve these docs ↗</a><a href="https://vstd-labs.com">About VSTD Labs ↗</a></div></aside></div>
<dialog class="search-dialog" aria-label="Search documentation"><form method="dialog"><label class="sr-only" for="docs-search">Search documentation</label><input id="docs-search" type="search" placeholder="Search concepts, commands, Python exports…" autocomplete="off"><button aria-label="Close search">Esc</button></form><div class="search-options"><label for="search-edition">Search in</label><select id="search-edition"><option value="all">All documentation</option><option value="release">Released {RELEASE}</option><option value="repository">Repository source</option></select></div><p class="search-status" role="status" aria-live="polite">Type to search.</p><div class="search-results"></div></dialog>
<noscript><p class="no-script">Search requires JavaScript. Browse the <a href="{link('guides.html')}">guide index</a> and <a href="{link(RELEASE_PATH + 'reference.html')}">package reference</a>.</p></noscript></body></html>'''


def search_entries(content: str, route: str, title: str) -> list[dict[str, str]]:
    edition = "release" if route.startswith(RELEASE_PATH) else "repository"
    sections = re.split(r'(?=<h[23]\b)', content)
    entries = []
    for section in sections:
        heading = re.match(r'<h[23]\b[^>]*id="([^"]+)"[^>]*>(.*?)</h[23]>', section, re.S)
        section_title = heading_text(heading.group(2)) if heading else title
        target = route + ("#" + heading.group(1) if heading else "")
        entries.append({"title": section_title, "page": title, "url": target,
                        "edition": edition, "text": plain(section)[:2200]})
    return entries


def build(output: Path, *, base_url: str = SITE) -> dict[str, object]:
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.path != "/" or parsed.query or parsed.fragment:
        raise ValueError("base URL must be an https origin with a trailing slash")
    output = output.resolve()
    if output == ROOT or output in ROOT.parents or (output.exists() and any(output.iterdir())):
        raise ValueError("portal output must be a new or empty directory outside repository sources")
    if output.is_relative_to(ROOT) and not output.is_relative_to(ROOT / "build"):
        raise ValueError("repository-local portal output belongs under build/")
    head = run(["git", "rev-parse", "HEAD"])
    dirty = bool(run(["git", "status", "--porcelain", "--untracked-files=normal"]))
    source_ref = "WORKTREE" if dirty else head
    with tempfile.TemporaryDirectory(prefix="verifier-docs-portal-") as temporary:
        release_source = Path(temporary) / "release-source"
        release_commit = export_release(release_source)
        assemble(ROOT, output, source_ref)
        assemble(release_source, output / RELEASE_PATH, release_commit)
    for name in ("portal.css", "portal.js", "portal-mark.svg"):
        shutil.copyfile(ASSETS / name, output / "assets" / name)
    for prefix in ("", RELEASE_PATH):
        coordinate_path = output / prefix / "documentation-coordinate.json"
        coordinate = json.loads(coordinate_path.read_text(encoding="utf-8"))
        coordinate["canonical_base_url"] = base_url + prefix
        coordinate_path.write_text(json.dumps(coordinate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    pages = sorted(output.rglob("*.html"))
    search = []
    for path in pages:
        route = path.relative_to(output).as_posix()
        page = path.read_text(encoding="utf-8")
        # Preserve schema identifiers and external resources; localize only site links.
        depth = len(Path(route).parts) - 1
        prefix = RELEASE_PATH if route.startswith(RELEASE_PATH) else ""
        page = re.sub(r'href="' + re.escape(OLD_SITE) + r'(?!schemas/)([^"]*)"',
                      lambda m: 'href="' + "../" * depth + prefix + m.group(1) + '"', page)
        content, title, outline = prepare_content(page)
        if route in ("index.html", RELEASE_PATH + "index.html"):
            content = home()
            content = content.replace('href="@/', 'href="' + "../" * depth)
            title = "Introduction"
            outline = [("start-building", "Start building"), ("explore", "Explore the documentation"), ("claim-boundaries", "Know what a result means")]
        source = release_commit if prefix else (head if not dirty else "main")
        # Release references must resolve to their tagged implementation, never main.
        if prefix:
            content = content.replace(REPOSITORY + "/blob/main/", REPOSITORY + "/blob/" + release_commit + "/")
            content = content.replace(REPOSITORY + "/tree/main/", REPOSITORY + "/tree/" + release_commit + "/")
        search.extend(search_entries(content, route, title))
        path.write_text(shell(content, route=route, title=title, outline=outline,
                              output=output, base_url=base_url, source_ref=source), encoding="utf-8", newline="\n")
    (output / "search-index.json").write_text(json.dumps(search, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    coordinate = {"schema_version": 1, "site": base_url, "repository": REPOSITORY,
                  "repository_head": head, "repository_source": source_ref,
                  "release_version": RELEASE, "release_tag": RELEASE_TAG,
                  "release_commit": release_commit, "release_origin": "Git release tag; distribution equivalence is a release-process dependency",
                  "schema_identifier_origin": OLD_SITE + "schemas/", "page_count": len(pages),
                  "search_entry_count": len(search), "deployment_status": "BUILT_NOT_DEPLOYED"}
    (output / "portal-coordinate.json").write_text(json.dumps(coordinate, indent=2) + "\n", encoding="utf-8")
    (output / "robots.txt").write_text("User-agent: *\nAllow: /\nSitemap: " + base_url + "sitemap.xml\n", encoding="utf-8")
    (output / "sitemap.xml").write_text('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + "".join('<url><loc>' + html.escape(base_url + path.relative_to(output).as_posix()) + '</loc></url>' for path in pages) + '</urlset>\n', encoding="utf-8")
    (output / "_headers").write_text("/*\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: strict-origin-when-cross-origin\n  X-Frame-Options: DENY\n  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' https: data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'\n", encoding="utf-8")
    manifest = {path.relative_to(output).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(output.rglob("*")) if path.is_file()}
    (output / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"[PORTAL OK] {len(pages)} pages; {len(search)} searchable sections", flush=True)
    return coordinate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--base-url", default=SITE)
    args = parser.parse_args()
    build(args.output, base_url=args.base_url)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
