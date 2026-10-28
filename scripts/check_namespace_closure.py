#!/usr/bin/env python3
"""Keep Verifier Standard (VSTD) namespace admission and legacy spellings closed.

Terminology: abstract syntax tree (AST).

The current VSTD-NAMESPACE has 38 object kinds and nine general meta-tiers.
`VSTD` names the standard, not a current object kind. The older numbered-profile
catalogue has 19 domain kinds, plus separate VSTD and Graph axes whose historical
receipt coordinates and wire identifiers are not renamed by this gate.

ALL-CAPS is the object-name marker. A `VSTD-` prefix on a current object remains
invalid; historical `VSTD-1` through `VSTD-6` and the `VSTD-NAMESPACE` title
remain admissible lexical references. Admission checks names and tier enum
meanings, not per-object objective registration or certification.
Readable obligation names are identifiers (IDs), not inferred aliases.  A registered
namespace-admission selector is an obligation selector, never an object identifier:
Python admits it only where the program passes it as an obligation, and every other
occurrence, including all non-Python text, is residue.

Run with no arguments; a non-zero exit names every offender.
"""

from __future__ import annotations

import ast
import io
import json
import re
import subprocess
import sys
import tokenize
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

#: Independent current specification inventory; compared with runtime ObjectKind.
OBJECTS: frozenset[str] = frozenset({
    "HUMAN", "ACTOR", "COLLECTIVE", "ROLE", "IDENTITY", "OWNER", "HARDWARE",
    "RECEIPT", "OBJECT", "GRAPH", "SPACE", "TIME", "EVENT", "ENV", "DATA",
    "VERIFIER", "BENCH", "ARCH", "TRAIN", "HYPER", "MODEL", "HARNESS",
    "AGENT", "SIM", "BOT", "TOKEN",
    "LEDGER", "TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR",
    "CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY", "ROBOT", "FINBOT",
})

#: The original wire enum remains fixed so historical receipts keep their
#: denominator while current admission grows through explicit refinements.
LEGACY_WIRE_OBJECTS: frozenset[str] = frozenset({
    "HUMAN", "ACTOR", "COLLECTIVE", "ROLE", "IDENTITY", "OWNER", "HARDWARE",
    "RECEIPT", "OBJECT", "GRAPH", "SPACE", "TIME", "EVENT", "ENV", "DATA",
    "VERIFIER", "BENCH", "ARCH", "TRAIN", "HYPER", "MODEL", "HARNESS",
    "AGENT", "SIM", "BOT", "TOKEN",
})

#: Earlier domain-object obligations retain exactly this nineteen-kind scope.
LEGACY_DOMAIN_OBJECTS: frozenset[str] = frozenset({
    "HUMAN", "ACTOR", "COLLECTIVE", "ROLE", "IDENTITY", "OWNER", "HARDWARE",
    "ENV", "DATA", "VERIFIER", "BENCH", "TRAIN", "HYPER", "MODEL",
    "HARNESS", "AGENT", "SIM", "BOT", "TOKEN",
})

#: General tier meanings, distinct from the retained numbered-profile catalogue.
CURRENT_TIERS: dict[int, str] = {
    1: "FACETS", 2: "DYNAMICS", 3: "STATICS", 4: "CLOSURE",
    5: "INDEPENDENCE", 6: "PRIVACY", 7: "CONSENT", 8: "GOVERNANCE",
    9: "SECURITY",
}

#: Named compositions that are *not* members of the namespace.  Empty by ruling.
#: Being written over other objects was once taken to disqualify a name from
#: membership, on the grounds that the namespace would stop being a basis.  TRAIN was
#: admitted anyway on 2026-09-22: composition is a property an object has, not a
#: reason it is not one, and TRAIN carries a substrate of its own -- a checkpoint
#: inventory and a step trace -- which `verifier.domains.train` replays.  What TRAIN
#: is composed of is recorded in COMPOSITION_OF, which is where that fact belongs.
#: The table stays because the question can recur: a head enters only with a
#: definition saying what it is composed of, and leaves only by being admitted to
#: OBJECTS or by ceasing to be named, never by being forgotten.
COMPOSITIONS: dict[str, str] = {}

#: Strings that contain an object name without naming an object.  Each carries
#: the reason it survives; a test requires the reason to be there.
EXCEPTIONS: dict[str, str] = {
    "VSTD-NAMESPACE": "the name of the space itself; a bare NAMESPACE is ambiguous",
    "VSTD-NAMESPACE-1.1": "the published example of an identifier that does not parse",
    "VSTD-INDIVIDUAL": "historical note: the object renamed to ROLE on 2026-09-21",
    "VSTD-Conformant": "prose adjective, not an identifier",
    "VSTD-ZK-EXPERIMENT-0.1": (
        "the profile label proven inside examples/zizk_artifact_first/risc0/recorded-proof; "
        "renaming it would claim a proof was run over a label it was not"
    ),
}

#: A token runs through every hyphen and dot, so a malformed separator stays part
#: of the token rather than leaving an admissible prefix behind.  Word characters
#: directly before `VSTD-` are walked back in residue_offenders, not matched here:
#: a leading `[A-Za-z0-9_]*` in the pattern rescans long runs and is quadratic.
_RESIDUE = re.compile(r"VSTD-[A-Za-z0-9][A-Za-z0-9.-]*")
_BASE_TIER = re.compile(r"[1-6](\.[1-9][0-9]*)?$")
#: `VSTD-N`, `VSTD-1..5`, `VSTD-1..VSTD-6`: a range or placeholder over the base
#: abstract's own tiers, which is prose about the ladder rather than a name on it.
_TIER_RANGE = re.compile(r"(N|[1-6]\.\.(VSTD-)?[1-6])$")
#: The original Graph ladder was a separate profile axis, not a GRAPH object
#: label.  These exact coordinate/range forms survive as historical grammar.
_HISTORICAL_GRAPH_PROFILE = re.compile(
    r"(?:GRAPH|Graph)-(N|[1-5](\.\.(VSTD-(?:GRAPH|Graph)-)?[1-5])?)$"
)
#: Any `T` followed by a digit after `VSTD-`: a Tier-0 spelling or a near miss of one.
_TIER_ZERO_SHAPE = re.compile(r"[Tt][0-9]")

#: Tier-0 coordinates VSTD-T0.1 through VSTD-T0.9, and the readable obligation
#: identifiers registered under them: a coordinate, a hyphen, then the slug of the
#: installed name in tier_zero_profile.py and standard/TIER_ZERO.md.  Closed: a
#: spelling is admitted only when it is exactly one of these, so a wrong tier, a
#: forged or truncated slug and a separator slip are not names of the standard.
#: Tier 4 has no entry here.
TIER_ZERO_COORDINATES: frozenset[str] = frozenset({
    "VSTD-T0.1", "VSTD-T0.2", "VSTD-T0.3", "VSTD-T0.4", "VSTD-T0.5",
    "VSTD-T0.6", "VSTD-T0.7", "VSTD-T0.8", "VSTD-T0.9",
})
#: A bare family prefix is used in source construction and in prose such as
#: "Tier-0 credit".  It is not an obligation identifier; every longer T0-shaped
#: spelling still has to match an exact coordinate or installed readable ID.
TIER_ZERO_PREFIX = "VSTD-T0"
TIER_ZERO_OBLIGATIONS: frozenset[str] = frozenset({
    "VSTD-T0.1-canonical-manifest-admission",
    "VSTD-T0.2-object-denominator-closure",
    "VSTD-T0.3-typed-relation-closure",
    "VSTD-T0.4-exposed-surface-closure",
    "VSTD-T0.5-obligation-denominator-closure",
    "VSTD-T0.6-reason-and-realization-closure",
    "VSTD-T0.7-source-and-mechanism-freshness",
    "VSTD-T0.8-independent-implementation-agreement",
    "VSTD-T0.9-conservative-verdict-and-authority-boundary",
})

#: Only explicit disposable working directories are outside the product scan.
#: Ordinary untracked source, tests, and documentation remain visible.  Git's
#: exclude rules remove repository-declared ignored files before this filter.
_SCRATCH_TEMP_CACHE_DIRS = frozenset({
    ".cache", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__",
    "cache", "caches", "scratch", "temp", "tmp",
})

#: Known binary/non-source formats are not decoded as product text.  Unknown
#: extensions remain fail-closed: if their bytes are textual, they are scanned.
_BINARY_NON_SOURCE_SUFFIXES = frozenset({
    ".7z", ".a", ".avi", ".bin", ".bmp", ".bz2", ".class", ".db", ".dll",
    ".dylib", ".eot", ".exe", ".gif", ".gz", ".ico", ".jar", ".jpeg",
    ".jpg", ".log", ".mkv", ".mov", ".mp3", ".mp4", ".o", ".obj", ".otf",
    ".pdf", ".pdb", ".pickle", ".pkl", ".png", ".pyc", ".pyd", ".so",
    ".sqlite", ".sqlite3", ".tar", ".tif", ".tiff", ".ttf", ".wav",
    ".webm", ".webp", ".whl", ".woff", ".woff2", ".xz", ".zip", ".zst",
})


@lru_cache(maxsize=1)
def installed_non_object_identifiers() -> frozenset[str]:
    """Read exact non-object identifiers from the installed authorities.

    This is deliberately narrow.  A string written in an ordinary source file,
    document, or test does not become authoritative merely by looking like a
    schema identifier.
    """

    from verifier import __standard__
    from verifier.core.geometry import GEOMETRY_SCHEMA_VERSION
    from verifier.core.receipt import CLAIM_SCHEMA_VERSION
    from verifier.core.run_support import RUN_SCHEMA_VERSION
    from verifier.environments.contracts import (
        EnvironmentDefinition,
        EnvironmentInstance,
        EnvironmentRunBinding,
    )
    from verifier.runtime.tier_zero_profile import installed_tier_zero_profile

    rows = installed_tier_zero_profile()["obligations"]
    coordinates = frozenset(row["coordinate"] for row in rows)
    obligations = frozenset(
        row["coordinate"] + "-"
        + re.sub(r"[^a-z0-9]+", "-", row["name"].lower()).strip("-")
        for row in rows
    )
    if coordinates != TIER_ZERO_COORDINATES or obligations != TIER_ZERO_OBLIGATIONS:
        raise RuntimeError("TIER_ZERO_IDENTIFIER_INVENTORY_DRIFT")
    return frozenset({
        __standard__, GEOMETRY_SCHEMA_VERSION, CLAIM_SCHEMA_VERSION,
        RUN_SCHEMA_VERSION, EnvironmentDefinition.SCHEMA,
        EnvironmentInstance.SCHEMA, EnvironmentRunBinding.SCHEMA,
        TIER_ZERO_PREFIX, *coordinates, *obligations,
    })


NAMESPACE_ADMISSION_SUFFIX = "-namespace-admission"
#: The gate calls whose second argument is the obligation selector.
OBLIGATION_GATE_CALLS: frozenset[str] = frozenset({"assess_gate", "assess_object_gate"})
OBLIGATION_KEY = "obligation_id"
TEST_FIXTURE_CONSTRUCTOR = "namespace_fixture_identifier"


def namespace_fixture_identifier(tail: str) -> str:
    """Construct an explicit adversarial namespace fixture for a test.

    The closure scanner recognizes calls to this function only below ``tests/``.
    This is a narrow, visible fixture channel: it does not exempt a test file,
    does not make the constructed identifier admissible, and has no effect when
    the resulting bytes are written into the product surface being checked.
    """

    if type(tail) is not str or not tail or "\n" in tail or "\r" in tail:
        raise ValueError("namespace fixture tail must be one non-empty line")
    return "VSTD-" + tail


@lru_cache(maxsize=1)
def registered_obligation_selectors() -> frozenset[str]:
    """The namespace-admission selectors the runtime registers, one per Tier-0 coordinate.

    They are read from the runtime's own registry and refused as drift unless they
    equal the coordinate inventory.  Being registered makes them obligation selectors;
    it does not make them admissible prose or object identifiers.
    """

    from verifier.runtime.manifest_gate import _admission_identities

    registered = frozenset(
        key for key in _admission_identities() if key.endswith(NAMESPACE_ADMISSION_SUFFIX)
    )
    expected = frozenset(
        coordinate + NAMESPACE_ADMISSION_SUFFIX for coordinate in TIER_ZERO_COORDINATES
    )
    if registered != expected:
        raise RuntimeError("NAMESPACE_ADMISSION_SELECTOR_DRIFT")
    return registered


def admissible(
        token: str, *, installed_identifiers: frozenset[str] | None = None,
        ) -> bool:
    """True for a retained VSTD-prefixed lexical spelling, not object admission."""

    if token == "VSTD" or token in EXCEPTIONS:
        return True
    if not token.startswith("VSTD-"):
        return False
    installed = installed_non_object_identifiers() \
        if installed_identifiers is None else installed_identifiers
    if token in installed:
        return True
    rest = token[len("VSTD-"):]
    if _TIER_ZERO_SHAPE.match(rest):    # any other T<digit> spelling is never prose
        return False
    if rest[:1].islower():              # VSTD-bound, VSTD-facing: hyphenated prose
        return True
    if _TIER_RANGE.fullmatch(rest):
        return True
    if _HISTORICAL_GRAPH_PROFILE.fullmatch(rest):
        return True
    return bool(_BASE_TIER.fullmatch(rest))


def catalogue_offenders() -> list[str]:
    """An added legacy catalogue object needs an explicit migration decision."""

    from verifier.core.profile_obligations import DOMAIN_OBJECTS

    return sorted(set(DOMAIN_OBJECTS) - LEGACY_DOMAIN_OBJECTS - set(COMPOSITIONS))


def catalogue_missing() -> list[str]:
    """The retained 19-domain catalogue cannot silently lose a domain object."""
    from verifier.core.profile_obligations import DOMAIN_OBJECTS

    return sorted(LEGACY_DOMAIN_OBJECTS - set(DOMAIN_OBJECTS))


def current_namespace_offenders() -> list[str]:
    """Check the independent name inventory against current admission."""
    from verifier.runtime.namespace_contracts import namespace_registry

    runtime = set(namespace_registry())
    return ([f"{name} missing from gate" for name in sorted(runtime - OBJECTS)]
            + [f"{name} absent from runtime" for name in sorted(OBJECTS - runtime)])


def legacy_wire_offenders() -> list[str]:
    """Keep historical ObjectKind receipt coordinates exactly 26-wide."""
    from verifier.core.namespace import ObjectKind

    runtime = {kind.value for kind in ObjectKind}
    return ([f"{name} missing from legacy wire gate"
             for name in sorted(runtime - LEGACY_WIRE_OBJECTS)]
            + [f"{name} absent from legacy wire enum"
               for name in sorted(LEGACY_WIRE_OBJECTS - runtime)])


def current_tier_offenders() -> list[str]:
    """A tier name or number must not drift without a reviewed spec change."""
    from verifier.core.namespace import MetaTier

    runtime = {tier.value: tier.name for tier in MetaTier}
    return [f"tier {number}: expected {CURRENT_TIERS.get(number)}, runtime {runtime.get(number)}"
            for number in sorted(set(CURRENT_TIERS) | set(runtime))
            if CURRENT_TIERS.get(number) != runtime.get(number)]


def _product_paths() -> list[str]:
    """Return the deterministic tracked plus nonignored-untracked product census."""

    listed = subprocess.run(
        [
            "git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others",
            "--exclude-standard",
        ],
        capture_output=True,
        check=True,
    ).stdout
    return sorted({
        encoded.decode("utf-8", errors="surrogateescape")
        for encoded in listed.split(b"\0")
        if encoded
    })


def _is_scannable_product_path(relative: str) -> bool:
    """Keep source-shaped product files; reject only explicit non-product forms."""

    logical = PurePosixPath(relative)
    if len(logical.parts) == 1 and logical.name.casefold() == "objects.vstd":
        return False
    if logical.suffix.casefold() == ".vstd":
        return False
    if any(part.casefold() in _SCRATCH_TEMP_CACHE_DIRS for part in logical.parts[:-1]):
        return False
    return logical.suffix.casefold() not in _BINARY_NON_SOURCE_SUFFIXES


def _normalize_residue_token(token: str) -> str:
    token = token.rstrip(".")
    for suffix in (".md", ".html", ".json", ".py", ".txt"):
        token = token[: -len(suffix)] if token.endswith(suffix) else token
    return token


def _tokens_in_text(text: str) -> frozenset[str]:
    return frozenset(
        _normalize_residue_token(match.group(0))
        for match in _RESIDUE.finditer(text)
    )


def _git_tokens_at_revision(
        root: Path, revision: str, paths: list[str],
        ) -> frozenset[str]:
    if not paths:
        return frozenset()
    found = subprocess.run(
        [
            "git", "-C", str(root), "grep", "-h", "-o", "-E",
            _RESIDUE.pattern, revision, "--", *paths,
        ],
        capture_output=True,
        check=False,
    )
    if found.returncode not in {0, 1}:
        return frozenset()
    return _tokens_in_text(found.stdout.decode("utf-8", errors="replace"))


@lru_cache(maxsize=32)
def _historical_context_identifiers(
        root_text: str,
        ) -> dict[str, frozenset[str]]:
    """Recover retained names from the exact source-feature base, by context.

    The generated source-feature manifest is an authoritative migration ledger,
    but it does not globally mint identifiers.  A name is historical here only
    when the manifest records it and it also occurs in the selected base bytes of
    a file whose entry records that migration.  The same spelling in an ordinary
    current document or test remains subject to normal admission.
    """

    root = Path(root_text)
    manifest_path = root / "docs" / "PR_SOURCE_FEATURES.json"
    try:
        manifest_text = manifest_path.read_text(encoding="utf-8")
        document = json.loads(manifest_text)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if type(document) is not dict or type(document.get("base")) is not str \
            or not re.fullmatch(r"[0-9a-f]{40}", document["base"]):
        return {}
    if type(document.get("files")) is not list:
        return {}

    relevant_paths: set[str] = set()
    for entry in document["files"]:
        if type(entry) is not dict or type(entry.get("path")) is not str:
            continue
        rendered = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        if not _RESIDUE.search(rendered):
            continue
        logical = PurePosixPath(entry["path"])
        if logical.is_absolute() or ".." in logical.parts:
            continue
        relevant_paths.add(logical.as_posix())

    base = document["base"]
    base_feature_tokens = _git_tokens_at_revision(
        root, base, sorted(relevant_paths)
    )
    base_tree = subprocess.run(
        ["git", "-C", str(root), "ls-tree", "-r", "--name-only", "-z", base],
        capture_output=True,
        check=False,
    )
    if base_tree.returncode == 0:
        base_paths = {
            encoded.decode("utf-8", errors="surrogateescape")
            for encoded in base_tree.stdout.split(b"\0")
            if encoded
        }
        base_feature_tokens = frozenset({
            *base_feature_tokens,
            *(
                token
                for path in relevant_paths & base_paths
                for token in _tokens_in_text(path)
            ),
        })
    manifest_tokens = _tokens_in_text(manifest_text)
    retained_manifest = {
        token for token in manifest_tokens & base_feature_tokens
        if not _TIER_ZERO_SHAPE.match(token[len("VSTD-"):])
    }
    # A migration summary may name an old schema family before listing its exact
    # members (for example, the former artifact schema spellings).  Admit that
    # family reference only in this ledger and only when the selected base really
    # contains a member of the family.
    for token in manifest_tokens - base_feature_tokens:
        if (_TIER_ZERO_SHAPE.match(token[len("VSTD-"):])
                or f"{token} spellings" not in manifest_text):
            continue
        if any(base_token.startswith(token + "-") for base_token in base_feature_tokens):
            retained_manifest.add(token)

    base_changelog = _git_tokens_at_revision(root, base, ["CHANGELOG.md"])
    return {
        "CHANGELOG.md": base_changelog,
        "docs/PR_SOURCE_FEATURES.json": frozenset(retained_manifest),
    }


def _call_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _text(node: ast.AST | None) -> str | None:
    """The text of a plain string literal, or None."""

    return node.value if isinstance(node, ast.Constant) and type(node.value) is str else None


def _fold(node: ast.AST | None) -> str | None:
    """The runtime text of a constant string expression, or None if any part is dynamic.

    Concatenation and escapes are folded, so `"VSTD-T0.2" + "-namespace-admission"` and an
    escaped `\\x2d` name the same text the program passes at runtime.
    """

    if isinstance(node, ast.Constant):
        if isinstance(node.value, bytes):
            return node.value.decode("utf-8", errors="replace")
        return node.value if type(node.value) is str else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _fold(node.left), _fold(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        texts = [_fold(part) for part in node.values]
        return None if any(text is None for text in texts) else "".join(
            text or "" for text in texts)
    return None


@dataclass(frozen=True)
class _ResolvedString:
    """A bounded statically resolved string and its explicit fixture provenance."""

    value: str
    fixture: bool = False


class _ConstantStringResolver:
    """Resolve a deliberately small constant-string subset of Python.

    This is not arbitrary runtime analysis.  It follows immutable module constants,
    single-return pure helpers, local helper assignments, string concatenation,
    constant f-strings, and constant ``join``/``format``/``replace`` calls.  Any
    branch, mutation, unknown call, recursion, or oversized value is left unresolved.
    """

    _MAX_DEPTH = 16
    _MAX_TEXT = 262_144

    def __init__(self, tree: ast.Module, *, allow_test_fixtures: bool) -> None:
        self.allow_test_fixtures = allow_test_fixtures
        self.helpers = {
            node.name: node for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and not node.decorator_list
        }
        candidates: dict[str, ast.expr] = {}
        repeated: set[str] = set()
        for node in tree.body:
            target: ast.Name | None = None
            value: ast.expr | None = None
            if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name):
                target, value = node.targets[0], node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) \
                    and isinstance(node.value, ast.expr):
                target, value = node.target, node.value
            if target is None or value is None:
                continue
            if target.id in candidates:
                repeated.add(target.id)
            else:
                candidates[target.id] = value
        self.constants = {
            name: value for name, value in candidates.items() if name not in repeated
        }

    @staticmethod
    def _merged(parts: list[_ResolvedString]) -> _ResolvedString | None:
        value = "".join(part.value for part in parts)
        if len(value) > _ConstantStringResolver._MAX_TEXT:
            return None
        return _ResolvedString(value, any(part.fixture for part in parts))

    def _sequence(
        self,
        node: ast.AST,
        *,
        local: dict[str, _ResolvedString],
        active: frozenset[str],
        depth: int,
    ) -> list[_ResolvedString] | None:
        if isinstance(node, ast.Name) and node.id not in local:
            target = self.constants.get(node.id)
            if target is None or node.id in active:
                return None
            return self._sequence(
                target, local=local, active=active | {node.id}, depth=depth + 1
            )
        if not isinstance(node, (ast.List, ast.Tuple)):
            return None
        values = [
            self.resolve(member, local=local, active=active, depth=depth + 1)
            for member in node.elts
        ]
        if any(value is None for value in values):
            return None
        return [value for value in values if value is not None]

    def resolve(
        self,
        node: ast.AST | None,
        *,
        local: dict[str, _ResolvedString] | None = None,
        active: frozenset[str] = frozenset(),
        depth: int = 0,
    ) -> _ResolvedString | None:
        if node is None or depth > self._MAX_DEPTH:
            return None
        local = {} if local is None else local
        if isinstance(node, ast.Constant):
            if type(node.value) is str:
                return _ResolvedString(node.value)
            if isinstance(node.value, bytes):
                return _ResolvedString(node.value.decode("utf-8", errors="replace"))
            return None
        if isinstance(node, ast.Name):
            if node.id in local:
                return local[node.id]
            target = self.constants.get(node.id)
            if target is None or node.id in active:
                return None
            return self.resolve(
                target, local=local, active=active | {node.id}, depth=depth + 1
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.resolve(node.left, local=local, active=active, depth=depth + 1)
            right = self.resolve(node.right, local=local, active=active, depth=depth + 1)
            return None if left is None or right is None else self._merged([left, right])
        if isinstance(node, ast.JoinedStr):
            parts: list[_ResolvedString] = []
            for value in node.values:
                target = value.value if isinstance(value, ast.FormattedValue) else value
                if isinstance(value, ast.FormattedValue) \
                        and (value.conversion != -1 or value.format_spec is not None):
                    return None
                resolved = self.resolve(
                    target, local=local, active=active, depth=depth + 1
                )
                if resolved is None:
                    return None
                parts.append(resolved)
            return self._merged(parts)
        if isinstance(node, ast.Call):
            return self._call(
                node, local=local, active=active, depth=depth + 1
            )
        return None

    def _call(
        self,
        node: ast.Call,
        *,
        local: dict[str, _ResolvedString],
        active: frozenset[str],
        depth: int,
    ) -> _ResolvedString | None:
        name = _call_name(node.func)
        if name == TEST_FIXTURE_CONSTRUCTOR \
                and len(node.args) == 1 and not node.keywords:
            tail = self.resolve(node.args[0], local=local, active=active, depth=depth + 1)
            if tail is None:
                return None
            try:
                value = namespace_fixture_identifier(tail.value)
            except ValueError:
                return None
            return _ResolvedString(value, self.allow_test_fixtures)

        if isinstance(node.func, ast.Attribute):
            receiver = self.resolve(
                node.func.value, local=local, active=active, depth=depth + 1
            )
            if receiver is None or node.keywords:
                return None
            try:
                if node.func.attr == "join" and len(node.args) == 1:
                    concrete = self._sequence(
                        node.args[0], local=local, active=active, depth=depth + 1
                    )
                    if concrete is None:
                        return None
                    value = receiver.value.join(member.value for member in concrete)
                    fixture = receiver.fixture or any(member.fixture for member in concrete)
                else:
                    arguments = [
                        self.resolve(
                            arg, local=local, active=active, depth=depth + 1
                        )
                        for arg in node.args
                    ]
                    if any(argument is None for argument in arguments):
                        return None
                    args = [argument for argument in arguments if argument is not None]
                    if node.func.attr == "format":
                        value = receiver.value.format(*(argument.value for argument in args))
                        fixture = receiver.fixture or any(argument.fixture for argument in args)
                    elif node.func.attr == "replace" and len(args) == 2:
                        value = receiver.value.replace(args[0].value, args[1].value)
                        fixture = receiver.fixture or any(argument.fixture for argument in args)
                    else:
                        return None
            except (IndexError, KeyError, ValueError):
                return None
            return None if len(value) > self._MAX_TEXT else _ResolvedString(value, fixture)

        helper = self.helpers.get(name or "")
        if helper is None or helper.name in active or helper.args.vararg is not None \
                or helper.args.kwarg is not None or helper.args.kwonlyargs:
            return None
        parameters = [*helper.args.posonlyargs, *helper.args.args]
        if len(node.args) > len(parameters):
            return None
        bindings: dict[str, _ResolvedString] = {}
        for parameter, argument in zip(parameters, node.args):
            resolved = self.resolve(
                argument, local=local, active=active, depth=depth + 1
            )
            if resolved is None:
                return None
            bindings[parameter.arg] = resolved
        for keyword in node.keywords:
            if keyword.arg is None or keyword.arg not in {p.arg for p in parameters} \
                    or keyword.arg in bindings:
                return None
            resolved = self.resolve(
                keyword.value, local=local, active=active, depth=depth + 1
            )
            if resolved is None:
                return None
            bindings[keyword.arg] = resolved
        missing = [parameter for parameter in parameters if parameter.arg not in bindings]
        defaults = [None] * (len(parameters) - len(helper.args.defaults)) \
            + list(helper.args.defaults)
        for parameter in missing:
            default = defaults[parameters.index(parameter)]
            if default is None:
                return None
            resolved = self.resolve(
                default, local=local, active=active, depth=depth + 1
            )
            if resolved is None:
                return None
            bindings[parameter.arg] = resolved

        helper_active = active | {helper.name}
        body = list(helper.body)
        if body and isinstance(body[0], ast.Expr) \
                and isinstance(body[0].value, ast.Constant) \
                and type(body[0].value.value) is str:
            body = body[1:]
        for index, statement in enumerate(body):
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1 \
                    and isinstance(statement.targets[0], ast.Name):
                value = self.resolve(
                    statement.value, local=bindings, active=helper_active, depth=depth + 1
                )
                if value is None:
                    return None
                bindings[statement.targets[0].id] = value
                continue
            if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name) \
                    and statement.value is not None:
                value = self.resolve(
                    statement.value, local=bindings, active=helper_active, depth=depth + 1
                )
                if value is None:
                    return None
                bindings[statement.target.id] = value
                continue
            if isinstance(statement, ast.Return) and index == len(body) - 1:
                return self.resolve(
                    statement.value, local=bindings, active=helper_active, depth=depth + 1
                )
            return None
        return None


def _parametrize_names(values: ast.AST, parents: dict[ast.AST, ast.AST]) -> list[str] | None:
    """The argnames of the pytest parametrize call that receives this values list."""

    call = parents.get(values)
    if not (isinstance(call, ast.Call) and _call_name(call.func) == "parametrize"
            and len(call.args) > 1 and call.args[1] is values):
        return None
    argnames = _text(call.args[0])
    return None if argnames is None else [name.strip() for name in argnames.split(",")]


def _is_key_subscript(node: ast.AST) -> bool:
    return isinstance(node, ast.Subscript) and _text(node.slice) == OBLIGATION_KEY


def _is_obligation_position(
        node: ast.AST, parents: dict[ast.AST, ast.AST], bound: frozenset[ast.AST],
        ) -> bool:
    """True when the program passes this expression to a gate as an obligation selector.

    Object, subject, node, and manifest identity positions are never obligation positions,
    so a registered selector there is refused.
    """

    parent = parents.get(node)
    if isinstance(parent, ast.keyword):
        return parent.arg == OBLIGATION_KEY
    if isinstance(parent, ast.Call):
        return (_call_name(parent.func) in OBLIGATION_GATE_CALLS
                and len(parent.args) > 1 and parent.args[1] is node)
    if isinstance(parent, ast.Dict):
        index = next((i for i, value in enumerate(parent.values) if value is node), None)
        return index is not None and _text(parent.keys[index]) == OBLIGATION_KEY
    if isinstance(parent, ast.Compare):
        return any(_is_key_subscript(other)
                   for other in (parent.left, *parent.comparators) if other is not node)
    if isinstance(parent, ast.Assign):
        return node is parent.value and any(_is_key_subscript(target) for target in parent.targets)
    if isinstance(parent, (ast.List, ast.Tuple)):
        index = next((i for i, element in enumerate(parent.elts) if element is node), None)
        if index is None:
            return False
        if index and _text(parent.elts[index - 1]) == "--obligation":   # rerun argv
            return True
        if parent in bound:                                              # iterated into a gate
            return True
        if isinstance(parent, ast.Tuple):                                # a parametrize row
            values = parents.get(parent)
            names = _parametrize_names(values, parents) if isinstance(values, ast.List) else None
            if names is None or len(names) < 2 or OBLIGATION_KEY not in names:
                return False
            return names.index(OBLIGATION_KEY) == index
        return _parametrize_names(parent, parents) == [OBLIGATION_KEY]
    return False


def _obligation_bound_lists(
        nodes: list[ast.AST], parents: dict[ast.AST, ast.AST],
        ) -> frozenset[ast.AST]:
    """Literal lists that a loop feeds, one hop, into an obligation position.

    `ids = [...]` followed by `f(obligation_id=item) for item in ids` makes the list's
    elements obligation selectors.  Only the direct loop shape is followed; anything else
    stays refused.
    """

    slot_names = {
        node.id for node in nodes
        if isinstance(node, ast.Name) and _is_obligation_position(node, parents, frozenset())
    }
    loop_names: set[str] = set()
    literals: set[ast.AST] = set()
    for node in nodes:
        if isinstance(node, (ast.For, ast.comprehension)) and isinstance(node.target, ast.Name) \
                and node.target.id in slot_names:
            if isinstance(node.iter, ast.Name):
                loop_names.add(node.iter.id)
            elif isinstance(node.iter, (ast.List, ast.Tuple)):
                literals.add(node.iter)
    for node in nodes:
        if isinstance(node, ast.Assign) and isinstance(node.value, (ast.List, ast.Tuple)) \
                and any(isinstance(target, ast.Name) and target.id in loop_names
                        for target in node.targets):
            literals.add(node.value)
    return frozenset(literals)


def _python_units(
        relative: str, text: str,
        ) -> list[tuple[int, str, bool, bool]] | None:
    """Each resolved string as (line, text, obligation slot, explicit fixture).

    None when the source does not parse, so the caller reads it as plain text and fails
    closed.  In addition to literal expressions, bounded pure helper calls are resolved.
    A string is a slot only when its whole runtime text is a registered selector in an
    obligation position.  The fixture bit is available only to explicit constructors in
    test files; writing the resulting bytes into another scanned file removes the bit.
    """

    try:
        tree = ast.parse(text)
        comments: list[tuple[int, str]] = []
        if "VSTD-" in text:        # a comment is never folded, so a selector in one is literal
            comments = [
                (token.start[0], token.string)
                for token in tokenize.generate_tokens(io.StringIO(text).readline)
                if token.type == tokenize.COMMENT
            ]
    except (SyntaxError, tokenize.TokenError, ValueError):
        return None
    pairs: list[tuple[ast.AST, ast.AST | None]] = []
    stack: list[tuple[ast.AST, ast.AST | None]] = [(tree, None)]
    while stack:                   # one traversal yields every node and its parent
        node, parent = stack.pop()
        pairs.append((node, parent))
        stack.extend((child, node) for child in ast.iter_child_nodes(node))
    nodes = [node for node, _ in pairs]
    parents = {node: parent for node, parent in pairs if parent is not None}
    resolver = _ConstantStringResolver(
        tree, allow_test_fixtures=PurePosixPath(relative).parts[:1] == ("tests",)
    )
    selectors = registered_obligation_selectors()
    bound: frozenset[ast.AST] | None = None     # computed only if a selector is present
    units = [(line, comment, False, False) for line, comment in comments]
    emitted: set[ast.AST] = set()
    for node in nodes:
        if not isinstance(node, ast.expr):
            continue
        plain = _fold(node)
        resolved = _ResolvedString(plain) if plain is not None else None
        maximal = node
        if resolved is None and isinstance(node, ast.Call):
            resolved = resolver.resolve(node)
            if resolved is not None:
                while isinstance(parents.get(maximal), ast.expr):
                    parent = parents[maximal]
                    parent_resolved = resolver.resolve(parent)
                    if parent_resolved is None:
                        break
                    maximal, resolved = parent, parent_resolved
        if resolved is None or maximal in emitted:
            continue
        if plain is not None and _fold(parents.get(node)) is not None:
            continue               # inside a larger literal; scan its maximal extent
        emitted.add(maximal)
        slot = False
        if resolved.value in selectors:
            if bound is None:
                bound = _obligation_bound_lists(nodes, parents)
            slot = _is_obligation_position(maximal, parents, bound)
        units.append((maximal.lineno, resolved.value, slot, resolved.fixture))
    return units


def _residue_tokens(text: str) -> list[tuple[int, str]]:
    """(line offset, normalized token) for each VSTD- token in a text unit."""

    found: list[tuple[int, str]] = []
    for match in _RESIDUE.finditer(text):
        begin = match.start()
        while begin and (text[begin - 1].isalnum() or text[begin - 1] == "_") \
                and not (begin >= 2 and text[begin - 2] == "\\"):
            begin -= 1                  # embedded in a larger word; `\b` is a boundary
        found.append((text.count("\n", 0, begin),
                      _normalize_residue_token(text[begin:match.end()])))
    return found


def _line_residue(text: str) -> list[tuple[int, str]]:
    """(line, token) for each VSTD- token in plain text, read line by line as always."""

    return [
        (number, token)
        for number, line in enumerate(text.splitlines(), start=1)
        for _, token in _residue_tokens(line)
    ]


def _python_occurrences(
        relative: str, text: str,
        ) -> list[tuple[int, str, bool, bool]]:
    """(line, token, obligation slot, fixture) for Python semantic strings.

    Python is read as its own strings and comments, so an escape or a concatenation names
    the same text the runtime sees.  A bounded pure helper call is handled the same way.
    Any other file, or Python that does not parse, is plain text without semantic slots.
    """

    if PurePosixPath(relative).suffix.casefold() == ".py":
        units = _python_units(relative, text)
        if units is not None:
            return [
                (line + offset, token, slot and token == value, fixture)
                for line, value, slot, fixture in units
                for offset, token in _residue_tokens(value)
            ]
    return [(line, token, False, False) for line, token in _line_residue(text)]


def _residue_reason(token: str, *, registered_selector: bool) -> str:
    if registered_selector:
        return "registered obligation selector used outside an exact obligation slot"
    if token.startswith("VSTD-") \
            and _TIER_ZERO_SHAPE.match(token[len("VSTD-"):]):
        return "unregistered Tier-0 obligation-shaped identifier"
    return "VSTD-prefixed identifier is not admitted at this product coordinate"


def residue_findings() -> list[tuple[str, int, str, str]]:
    """Return exact file, line, token, and reason for each namespace residue."""

    found: list[tuple[str, int, str, str]] = []
    installed = installed_non_object_identifiers()
    selectors = registered_obligation_selectors()
    historical = _historical_context_identifiers(str(ROOT.resolve()))
    for relative in _product_paths():
        if not _is_scannable_product_path(relative):
            continue
        path = ROOT / relative
        try:
            content = path.read_bytes()
        except OSError:
            continue
        if b"\0" in content:
            continue
        text = content.decode("utf-8", errors="replace")
        line_residue = _line_residue(text)
        lexical_pairs = set(line_residue)
        for number, token in line_residue:
            if token not in selectors and token not in historical.get(relative, frozenset()) \
                    and not admissible(token, installed_identifiers=installed):
                found.append((relative, number, token, _residue_reason(
                    token, registered_selector=False)))
        for number, token, slot, fixture in _python_occurrences(relative, text):
            if fixture:
                continue
            if token in selectors:
                if not slot:
                    finding = (relative, number, token, _residue_reason(
                        token, registered_selector=True))
                    if finding not in found:
                        found.append(finding)
            elif token.startswith("VSTD-") \
                    and _TIER_ZERO_SHAPE.match(token[len("VSTD-"):]) \
                    and (number, token) not in lexical_pairs \
                    and token not in historical.get(relative, frozenset()) \
                    and not admissible(token, installed_identifiers=installed):
                found.append((relative, number, token, _residue_reason(
                    token, registered_selector=False)))
    return sorted(found)


def residue_offenders() -> list[tuple[str, int, str]]:
    """Compatibility view of residue findings without the diagnostic reason."""

    return [(relative, line, token)
            for relative, line, token, _ in residue_findings()]


def main() -> int:
    catalogue = catalogue_offenders()
    missing = catalogue_missing()
    current = current_namespace_offenders()
    legacy_wire = legacy_wire_offenders()
    tiers = current_tier_offenders()
    residue = residue_findings()

    if catalogue:
        print(f"[NAMESPACE CLOSURE] FAIL: {len(catalogue)} object(s) outside the legacy nineteen:")
        for name in catalogue:
            print(f"  the catalogue carries {name}")
    if missing:
        print("[NAMESPACE CLOSURE] FAIL: legacy domain objects without obligations: " + ", ".join(missing))
    for offender in current + legacy_wire + tiers:
        print("[NAMESPACE CLOSURE] FAIL: " + offender)
    if residue:
        print(f"[NAMESPACE CLOSURE] FAIL: {len(residue)} VSTD- prefix(es) that should be bare:")
        for relative, number, token, reason in residue:
            print(f"  {relative}:{number}: {token} -- {reason}")
    if catalogue or missing or current or legacy_wire or tiers or residue:
        print(
            "\nThe current VSTD-NAMESPACE contains "
            + ", ".join(sorted(OBJECTS))
            + ".\nThe 19-object legacy domain catalogue retains old profile meanings."
            "\nThe VSTD- prefix survives historical profile references and the"
            " VSTD-NAMESPACE title, not current object identifiers."
        )
        return 1

    print(
        f"[NAMESPACE CLOSURE] PASS: {len(OBJECTS)} object kinds and nine meta-tiers "
        "match the current runtime; structural admission only; "
        "objective certification NOT_ESTABLISHED. The 26-kind wire enum, 19-object "
        "legacy domain catalogue, and historical VSTD-1..VSTD-6 spellings retain "
        "their old meanings."
    )
    for name, definition in COMPOSITIONS.items():
        print(f"[NAMESPACE CLOSURE] COMPOSITION: {name} -- {definition}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
