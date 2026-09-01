#!/usr/bin/env python3
"""Audit external Hypertext Transfer Protocol (HTTP) documentation links."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import time
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urldefrag
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ALLOWLIST = ROOT / ".github/external-links-allowlist.txt"
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\((https?://[^)\s]+)(?:\s+[^)]*)?\)")


class _HtmlLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in {"a", "img", "link", "script"}:
            return
        attributes = dict(attrs)
        value = attributes.get("href") or attributes.get("src")
        if value and value.startswith(("http://", "https://")):
            self.links.append(value)


@dataclass(frozen=True)
class Result:
    url: str
    status: str
    detail: str


def collect_links(paths: Iterable[Path]) -> tuple[str, ...]:
    links: set[str] = set()
    for path in paths:
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".html":
            parser = _HtmlLinks()
            parser.feed(text)
            links.update(parser.links)
        elif path.suffix.lower() == ".md":
            links.update(match.group(1) for match in MARKDOWN_LINK.finditer(text))
    return tuple(sorted({urldefrag(link)[0] for link in links}))


def documentation_paths(root: Path) -> tuple[Path, ...]:
    excluded = {".git", "build", "dist", "artifacts_tmp"}
    return tuple(
        path
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and path.suffix.lower() in {".html", ".md"}
        and not excluded.intersection(path.relative_to(root).parts)
    )


def read_allowlist(path: Path) -> tuple[tuple[str, str], ...]:
    entries: list[tuple[str, str]] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw or raw.startswith("#"):
            continue
        try:
            pattern, reason = raw.split("\t", 1)
        except ValueError as exc:
            raise ValueError(f"{path}:{number}: allowlist entry needs a tab and reason") from exc
        if not pattern.startswith(("http://", "https://")) or not reason.strip():
            raise ValueError(f"{path}:{number}: invalid allowlist entry")
        entries.append((pattern, reason.strip()))
    return tuple(entries)


def allowlist_reason(url: str, entries: Iterable[tuple[str, str]]) -> str | None:
    for pattern, reason in entries:
        if (pattern.endswith("*") and url.startswith(pattern[:-1])) or url == pattern:
            return reason
    return None


def _request(url: str, method: str, timeout: float) -> int:
    headers = {"User-Agent": "TimeLordRaps-verifier-link-audit/1.0"}
    if method == "GET":
        headers["Range"] = "bytes=0-0"
    request = Request(url, headers=headers, method=method)
    with urlopen(request, timeout=timeout) as response:
        return int(response.status)


def probe(url: str, *, retries: int, timeout: float) -> Result:
    last = "no attempt"
    for attempt in range(retries + 1):
        try:
            return Result(url, "OK", str(_request(url, "HEAD", timeout)))
        except HTTPError as exc:
            if exc.code in {403, 405}:
                try:
                    return Result(url, "OK", str(_request(url, "GET", timeout)))
                except (HTTPError, URLError, TimeoutError, OSError) as get_exc:
                    last = str(get_exc)
            else:
                last = str(exc)
        except (URLError, TimeoutError, OSError) as exc:
            last = str(exc)
        if attempt < retries:
            time.sleep(2**attempt)
    return Result(url, "FAILED", last)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument("--report", type=Path, default=Path("external-links.json"))
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args(argv)

    entries = read_allowlist(args.allowlist)
    pending: list[str] = []
    results: list[Result] = []
    for url in collect_links(documentation_paths(ROOT)):
        reason = allowlist_reason(url, entries)
        if reason:
            results.append(Result(url, "ALLOWLISTED", reason))
        else:
            pending.append(url)
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        results.extend(
            executor.map(
                lambda url: probe(url, retries=args.retries, timeout=args.timeout), pending
            )
        )
    results.sort(key=lambda result: result.url)
    payload = {
        "schema_version": 1,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "results": [asdict(result) for result in results],
    }
    args.report.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    failures = [result for result in results if result.status == "FAILED"]
    print(f"[LINK AUDIT] checked={len(results)} failed={len(failures)}")
    for result in failures:
        print(f"[FAILED] {result.url}: {result.detail}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
