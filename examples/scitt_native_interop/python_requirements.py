"""Supply Chain Integrity, Transparency, and Trust (SCITT) requirement consistency.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Unicode Transformation Format, 8-bit (UTF-8); uniform resource locator (URL);
American Standard Code for Information Interchange (ASCII).
Inspect bounded ordinary installed distribution METADATA without importing its
code. Offline rechecking uses only retained reachable metadata, exact root pins,
an explicit complete marker environment, and the selected packaging 26.3 parser.
CONSISTENT means only that the retained declared requirements match retained
provider versions under that environment. It does not prove provider inventory
completeness, a current installation, executable files, runtime qualification,
package dependency resolution, independence, or authorization. Parser source
hashes observe selected files, not loaded-byte authenticity or a hostile sandbox.
Metadata may contain private descriptive information: capture outside public
source and review disclosure separately. No network, installation, or native run.
Legacy egg-info supplies only name/version indexing, never interpreted dependency
coverage. Metadata-Version 2.0 is likewise indexed, not interpreted as supported.
An explicitly empty Requires-Python specifier means no restriction,
as interpreted by the pinned parser; an absent header remains NOT_DECLARED.
"""

from __future__ import annotations

import base64
from email import policy
from email.parser import Parser
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

if __package__:
    from .native_runner import _ordinary, read_regular
else:
    from native_runner import _ordinary, read_regular


PARSER_VERSION = "26.3"
SCITT_ROOTS = {"scitt-cose": "0.2.2", "cbor2": "6.1.4", "cryptography": "50.0.0"}
ENVIRONMENT_KEYS = frozenset(("implementation_name", "implementation_version", "os_name", "platform_machine",
    "platform_release", "platform_system", "platform_version", "python_full_version",
    "platform_python_implementation", "python_version", "sys_platform", "extra"))
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_DOCUMENTS = 128
MAX_RETAINED_BYTES = 16 * 1024 * 1024
MAX_DISCOVERY_DOCUMENTS = 1024
MAX_DISCOVERY_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 8192
MAX_EDGES = 2048
FORMAT = "SCITT-PYTHON-REQUIREMENTS-1"
SUPPORTED_METADATA_VERSIONS = frozenset(("2.1", "2.2", "2.3", "2.4", "2.5", "2.6"))
BOUNDARY = "Retained installed-distribution requirement consistency only; no inventory completeness, current-installation, executable integrity, runtime qualification, package dependency resolution, or authority established."


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _hex(value: Any) -> str:
    if type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None:
        raise ValueError("exact lowercase digest required")
    return value


def _text(value: Any, limit: int = 256) -> str:
    if type(value) is not str or len(value) > limit or any(ord(char) < 32 for char in value):
        raise ValueError("bounded plain text required")
    return value


def _parser() -> tuple[Any, Any, Any]:
    try:
        import packaging
        from packaging.requirements import Requirement
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version
    except ImportError as exc:
        raise ValueError("optional host-selected packaging 26.3 parser unavailable") from exc
    if packaging.__version__ != PARSER_VERSION:
        raise ValueError("exact packaging 26.3 parser required")
    return Requirement, SpecifierSet, Version


def _parser_coordinate() -> dict[str, Any]:
    _parser()
    import packaging
    import packaging.requirements
    import packaging.specifiers
    import packaging.version
    root = Path(packaging.__file__).absolute().parent
    _ordinary(root, directory=True)
    parser_modules = (
        ("packaging", packaging),
        ("packaging.requirements", packaging.requirements),
        ("packaging.specifiers", packaging.specifiers),
        ("packaging.version", packaging.version),
    )
    for name, module in parser_modules:
        location = getattr(module, "__file__", None)
        base = root if name == "packaging" else root.joinpath(*name.split(".")[1:])
        allowed = (base / "__init__.py",) if name == "packaging" else (base.with_suffix(".py"), base / "__init__.py")
        if type(location) is not str or Path(os.path.abspath(location)) not in allowed:
            raise ValueError("mixed parser import source locations")
        _ordinary(Path(location), directory=False)
    sources, pending, count, total = {}, [root], 0, 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for item in entries:
                count += 1
                if count > 256: raise ValueError("parser source walk bound exceeded")
                path = Path(item.path)
                if item.is_dir(follow_symlinks=False):
                    _ordinary(path, directory=True)
                    if item.name != "__pycache__": pending.append(path)
                elif path.suffix.casefold() == ".py":
                    if path.suffix != ".py": raise ValueError("noncanonical parser source suffix")
                    raw = read_regular(path, MAX_DOCUMENT_BYTES)
                    total += len(raw)
                    if len(sources) >= 64 or total > 8 * MAX_DOCUMENT_BYTES: raise ValueError("parser source byte/file bound exceeded")
                    name = path.relative_to(root).as_posix()
                    if name.casefold() in {key.casefold() for key in sources}: raise ValueError("ambiguous parser source names")
                    sources[name] = _sha(raw)
    if "__init__.py" not in sources: raise ValueError("ordinary parser source checkout required")
    return {"distribution": "packaging", "version": PARSER_VERSION, "source_sha256": sources,
            "checker_sha256": _sha(read_regular(Path(__file__).absolute(), MAX_DOCUMENT_BYTES))}


def _name(value: Any) -> str:
    value = _text(value)
    if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", value) is None:
        raise ValueError("invalid distribution name")
    return re.sub(r"[-_.]+", "-", value).lower()


def _context(roots: Any, environment: Any) -> tuple[dict[str, str], dict[str, str]]:
    _, _, Version = _parser()
    if type(roots) is not dict or not 1 <= len(roots) <= 32:
        raise ValueError("bounded explicit exact root pins required")
    copied = {}
    for name, version in roots.items():
        if _name(name) != name or str(Version(_text(version))) != version:
            raise ValueError("root names and exact versions must be canonical")
        copied[name] = version
    if type(environment) is not dict or set(environment) != ENVIRONMENT_KEYS:
        raise ValueError("complete explicit marker environment required")
    env = {key: _text(value) for key, value in environment.items()}
    if env["extra"] != "": raise ValueError("requested extras are outside this contract")
    for key in ("python_version", "python_full_version", "implementation_version"):
        Version(env[key])
    version = Version(env["python_full_version"])
    if env["python_version"] != ".".join(map(str, version.release[:2])):
        raise ValueError("Python version environment fields disagree")
    return copied, env


def _requirement_text(value: str) -> str:
    text = value.replace("\r\n", " ").replace("\n", " ").replace("\t", " ")
    _text(text, 4096)
    if not text.isascii(): raise ValueError("requirement text must be ASCII")
    depth, quote = 0, ""
    for char in text:
        if quote:
            if char == quote: quote = ""
        elif char in "\"'": quote = char
        elif char == "(":
            depth += 1
            if depth > 16: raise ValueError("requirement nesting bound exceeded")
        elif char == ")": depth -= 1
    return text


def _metadata(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > MAX_DOCUMENT_BYTES:
        raise ValueError("bounded raw metadata bytes required")
    _, _, Version = _parser()
    message = Parser(policy=policy.compat32).parsestr(raw.decode("utf-8"), headersonly=True)
    if message.defects or message.is_multipart(): raise ValueError("malformed distribution metadata")
    result = {}
    for key in ("Metadata-Version", "Name", "Version", "Requires-Python"):
        values = message.get_all(key, [])
        if len(values) > 1 or (key != "Requires-Python" and len(values) != 1):
            raise ValueError("missing or duplicate singleton metadata header")
        result[key] = _text(values[0]) if values else None
    if result["Metadata-Version"] not in SUPPORTED_METADATA_VERSIONS | {"2.0"}:
        raise ValueError("unsupported metadata version")
    result["name"] = _name(result["Name"])
    Version(result["Version"])
    requirements = message.get_all("Requires-Dist", [])
    if len(requirements) > MAX_EDGES: raise ValueError("metadata requirement count bound exceeded")
    result["requires_dist"] = ([_requirement_text(value) for value in requirements]
                               if result["Metadata-Version"] in SUPPORTED_METADATA_VERSIONS else [])
    return result


def _active(text: str, environment: dict[str, str]) -> tuple[Any, str]:
    Requirement, _, _ = _parser()
    requirement = Requirement(text)
    if requirement.marker is not None:
        unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", "", str(requirement.marker))
        if re.search(r"\b(extras|dependency_groups)\b", unquoted):
            raise ValueError("unsupported marker context")
        if not requirement.marker.evaluate(environment=dict(environment), context="metadata"):
            return requirement, "INACTIVE"
    if requirement.url is not None or requirement.extras:
        return requirement, "UNKNOWN"
    return requirement, "ACTIVE"


def _evaluate(roots: dict[str, str], environment: dict[str, str], documents: list[dict[str, str]]) -> tuple[dict[str, Any], set[str]]:
    _, SpecifierSet, Version = _parser()
    providers: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for document in documents:
        metadata = _metadata(base64.b64decode(document["metadata_b64"], validate=True))
        metadata["layout"] = document["layout"]
        providers.setdefault(metadata["name"], []).append((document["provider_id"], metadata))
    queue, visited, used, nodes, edges, unknown, mismatch = list(sorted(roots)), set(), set(), [], [], False, False

    def target(name: str, specifier: Any = None, exact: str | None = None) -> tuple[str, str | None]:
        nonlocal unknown, mismatch
        candidates = providers.get(name, [])
        used.update(item[0] for item in candidates)
        if len(candidates) != 1:
            unknown = True
            return ("MISSING_PROVIDER" if not candidates else "AMBIGUOUS_PROVIDER"), None
        version = candidates[0][1]["Version"]
        unsupported = candidates[0][1]["layout"] != "dist-info" or candidates[0][1]["Metadata-Version"] not in SUPPORTED_METADATA_VERSIONS
        unknown |= unsupported
        if (exact is not None and version != exact) or (specifier is not None and not specifier.contains(Version(version), prereleases=True)):
            mismatch = True
            return "MISMATCH", version
        if unsupported: return "UNSUPPORTED_PROVIDER", version
        return "MATCHED", version

    root_results = []
    for name, version in sorted(roots.items()):
        status, installed = target(name, exact=version)
        root_results.append({"name": name, "expected_version": version, "retained_version": installed, "status": status})
    while queue:
        name = queue.pop(0)
        if name in visited: continue
        visited.add(name)
        candidates = providers.get(name, [])
        if len(candidates) != 1: continue
        identity, metadata = candidates[0]
        used.add(identity)
        python_requirement = metadata["Requires-Python"]
        if metadata["layout"] != "dist-info" or metadata["Metadata-Version"] not in SUPPORTED_METADATA_VERSIONS:
            unknown = True
            nodes.append({"name": name, "provider_id": identity, "layout": metadata["layout"], "metadata_version": metadata["Metadata-Version"], "version": metadata["Version"], "requires_python": python_requirement,
                          "python_status": "UNSUPPORTED_LAYOUT" if metadata["layout"] != "dist-info" else "UNSUPPORTED_METADATA_VERSION"})
            continue
        python_status = "NOT_DECLARED"
        if python_requirement is not None:
            try:
                python_status = "MATCHED" if SpecifierSet(_requirement_text(python_requirement)).contains(Version(environment["python_full_version"]), prereleases=True) else "MISMATCH"
                mismatch |= python_status == "MISMATCH"
            except ValueError:
                python_status, unknown = "UNKNOWN", True
        nodes.append({"name": name, "provider_id": identity, "layout": metadata["layout"], "metadata_version": metadata["Metadata-Version"], "version": metadata["Version"], "requires_python": python_requirement, "python_status": python_status})
        for index, text in enumerate(metadata["requires_dist"]):
            if len(edges) >= MAX_EDGES: raise ValueError("active traversal edge bound exceeded")
            edge = {"source": name, "requirement_index": index, "requirement": text, "target": None, "retained_version": None, "status": "UNKNOWN"}
            try:
                requirement, state = _active(text, environment)
                dependency = _name(requirement.name)
                edge["target"] = dependency
                if state == "ACTIVE":
                    edge["status"], edge["retained_version"] = target(dependency, requirement.specifier)
                    queue.append(dependency)
                else:
                    edge["status"] = state
                    unknown |= state == "UNKNOWN"
            except (ValueError, KeyError):
                unknown = True
            edges.append(edge)
    return {"status": "INCONSISTENT" if mismatch else "UNKNOWN" if unknown else "CONSISTENT", "roots": root_results,
            "providers": sorted(nodes, key=lambda item: item["name"]), "edges": edges, "claim_boundary": BOUNDARY}, used


def _admit(snapshot: Any) -> dict[str, Any]:
    if type(snapshot) is not dict or set(snapshot) != {"schema_version", "roots", "environment", "parser", "discovery", "documents"} or type(snapshot["schema_version"]) is not str or snapshot["schema_version"] != FORMAT:
        raise ValueError("exact requirement snapshot fields required")
    roots, environment = _context(snapshot["roots"], snapshot["environment"])
    documents = snapshot["documents"]
    if type(documents) is not list or len(documents) > MAX_DOCUMENTS: raise ValueError("retained document count bound exceeded")
    copied, identities, total = [], set(), 0
    for item in documents:
        if type(item) is not dict or set(item) != {"provider_id", "metadata_b64", "layout"} or type(item["provider_id"]) is not str or re.fullmatch(r"provider:[0-9]{1,4}", item["provider_id"]) is None or item["provider_id"] in identities:
            raise ValueError("unique exact retained provider identity required")
        if type(item["layout"]) is not str or item["layout"] not in ("dist-info", "egg-info"):
            raise ValueError("explicit supported index layout required")
        encoded = item["metadata_b64"]
        if type(encoded) is not str or len(encoded) > (MAX_DOCUMENT_BYTES + 2) // 3 * 4: raise ValueError("encoded metadata exceeds bound")
        raw = base64.b64decode(encoded, validate=True)
        if base64.b64encode(raw).decode("ascii") != encoded: raise ValueError("noncanonical encoded metadata")
        _metadata(raw)
        total += len(raw)
        if total > MAX_RETAINED_BYTES: raise ValueError("retained metadata byte bound exceeded")
        identities.add(item["provider_id"])
        copied.append(dict(item))
    parser = snapshot["parser"]
    if type(parser) is not dict or set(parser) != {"distribution", "version", "source_sha256", "checker_sha256"} or type(parser["distribution"]) is not str or type(parser["version"]) is not str or parser["distribution"] != "packaging" or parser["version"] != PARSER_VERSION:
        raise ValueError("exact parser coordinate required")
    _hex(parser["checker_sha256"])
    sources = parser["source_sha256"]
    if type(sources) is not dict or not 1 <= len(sources) <= 64: raise ValueError("bounded parser source inventory required")
    for name, digest in sources.items():
        if type(name) is not str or len(name) > 256 or re.fullmatch(r"(?:[A-Za-z_][A-Za-z_0-9]*/)*[A-Za-z_][A-Za-z_0-9]*\.py", name) is None: raise ValueError("invalid parser source location")
        _hex(digest)
    discovery = snapshot["discovery"]
    if type(discovery) is not dict or set(discovery) != {"root_path_sha256", "provider_count", "metadata_bytes"}: raise ValueError("exact observed discovery scope required")
    locators = discovery["root_path_sha256"]
    if type(locators) is not list or not 1 <= len(locators) <= 8 or any(type(value) is not str for value in locators) or len(set(locators)) != len(locators): raise ValueError("bounded distinct discovery root locators required")
    for value in locators: _hex(value)
    for key, lower, upper in (("provider_count", len(copied), MAX_DISCOVERY_DOCUMENTS), ("metadata_bytes", total, MAX_DISCOVERY_BYTES)):
        if type(discovery[key]) is not int or not lower <= discovery[key] <= upper: raise ValueError("invalid observed discovery count")
    return {"schema_version": FORMAT, "roots": roots, "environment": environment,
            "parser": {"distribution": "packaging", "version": PARSER_VERSION, "source_sha256": dict(sources), "checker_sha256": parser["checker_sha256"]},
            "discovery": {**discovery, "root_path_sha256": list(locators)}, "documents": copied}


def snapshot_digest(snapshot: dict[str, Any]) -> str:
    return _sha(canonical(_admit(snapshot)))


def capture_requirements(roots: dict[str, str], *, environment: dict[str, str], search_paths: tuple[Path, ...]) -> dict[str, Any]:
    """Observe explicitly selected ordinary dist-info directories; retain reachable metadata."""
    roots, environment = _context(roots, environment)
    parser = _parser_coordinate()
    if type(search_paths) is not tuple or not 1 <= len(search_paths) <= 8: raise ValueError("explicit bounded discovery roots required")
    paths = [Path(os.path.abspath(path)) for path in search_paths]
    if len({str(path).casefold() for path in paths}) != len(paths): raise ValueError("duplicate discovery roots")
    documents, entries_seen, total = [], 0, 0
    for root in paths:
        _ordinary(root, directory=True)
        entries = []
        with os.scandir(root) as iterator:
            for item in iterator:
                entries_seen += 1
                if entries_seen > MAX_ENTRIES: raise ValueError("distribution discovery entry bound exceeded")
                entries.append(item)
        for item in sorted(entries, key=lambda value: value.name):
            if item.name.casefold().endswith(".egg"):
                raise ValueError("unsupported provider layout in selected discovery root")
            if not item.name.casefold().endswith((".dist-info", ".egg-info")): continue
            layout = "egg-info" if item.name.casefold().endswith(".egg-info") else "dist-info"
            if not item.name.endswith("." + layout): raise ValueError("noncanonical provider layout")
            directory = Path(item.path)
            if layout == "egg-info" and not item.is_dir(follow_symlinks=False):
                raw = read_regular(directory, MAX_DOCUMENT_BYTES)
            else:
                _ordinary(directory, directory=True)
                raw = read_regular(directory / ("PKG-INFO" if layout == "egg-info" else "METADATA"), MAX_DOCUMENT_BYTES)
            total += len(raw)
            if total > MAX_DISCOVERY_BYTES or len(documents) >= MAX_DISCOVERY_DOCUMENTS: raise ValueError("distribution discovery metadata bound exceeded")
            _metadata(raw)
            documents.append({"provider_id": "provider:" + str(len(documents)), "layout": layout, "metadata_b64": base64.b64encode(raw).decode("ascii")})
    _, used = _evaluate(roots, environment, documents)
    snapshot = {"schema_version": FORMAT, "roots": roots, "environment": environment, "parser": parser,
                "discovery": {"root_path_sha256": [_sha(str(path).encode("utf-8")) for path in paths], "provider_count": len(documents), "metadata_bytes": total},
                "documents": [item for item in documents if item["provider_id"] in used]}
    if _parser_coordinate() != parser: raise ValueError("parser sources changed during capture")
    return _admit(snapshot)


def recheck_requirements(snapshot: dict[str, Any], *, expected_snapshot_digest: str) -> dict[str, Any]:
    """Offline re-evaluate retained declarations; never rediscover installed providers."""
    expected = _hex(expected_snapshot_digest)
    snapshot = _admit(snapshot)
    if _sha(canonical(snapshot)) != expected: raise ValueError("snapshot differs from separately supplied digest")
    parser = _parser_coordinate()
    if parser != snapshot["parser"]: raise ValueError("parser source coordinate differs")
    report, used = _evaluate(snapshot["roots"], snapshot["environment"], snapshot["documents"])
    if used != {item["provider_id"] for item in snapshot["documents"]}: raise ValueError("snapshot contains unrelated provider metadata")
    if _parser_coordinate() != parser: raise ValueError("parser sources changed during recheck")
    return {"snapshot_digest": expected, **report, "native_execution_performed": False, "installed_inventory_rechecked": False}
