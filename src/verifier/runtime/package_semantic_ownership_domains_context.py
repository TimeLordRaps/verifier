"""Audited original-domain ownership for ten retained primary kinds.

Terminology: JavaScript Object Notation (JSON).

Terminology: abstract syntax tree (AST); environment (ENV); event (EVENT);
graph (GRAPH); hypergraph (HYPER); identity (IDENTITY); owner (OWNER); receipt
(RECEIPT); role (ROLE); space (SPACE); time (TIME); Verifier Standard (VSTD).

This data-first module declares exactly 41 source paths across the ENV, EVENT,
GRAPH, HYPER, IDENTITY, SPACE, TIME, ROLE, OWNER and RECEIPT primary kinds.  It
imports only the model constructors from the model module and never imports the
aggregate catalog.

Decisions are object-level accumulations over the owned paths.  Each of the
twelve registered accumulating roles and the VERIFIER root role is decided
APPLIES, DOES_NOT_APPLY or UNKNOWN.  An APPLIES cites the owned-file symbols that
establish it, with line spans recorded from the source.  A DOES_NOT_APPLY cites
every owned file whole, and its absence claim is checked mechanically by an AST
test over the whole bytes, dead lines included.  UNKNOWN is a first-class status: it cites the
symbols where a role's signal appears, names the unresolved semantics, never
enters a specialization, is never counted as DOES_NOT_APPLY, and blocks
aggregation through ``aggregation_blockers`` and ``require_aggregation_ready``.
OBJECT is never fallback.

Gate normalization: role tests are AST predicates over the executable source.
Docstrings, comments and prose strings contribute no tokens, so a prose-only mention
establishes or denies no role.  Identifiers, attribute and keyword names and
single-token string keys are matched.  Dead statements are recorded and never
establish APPLIES; a DOES_NOT_APPLY file carries no test hit, dead or live.

Decision rules applied uniformly: SENSOR applies only when a file acquires a
phenomenon with calibration, sampling, sensor, transducer, acquisition or fault
semantics; a file, digest, clock, platform or subprocess read alone never does.
ACTUATOR applies only to runtime dispatch of a data-chosen coordinate through a
route registry, never to a fixed call into a sibling module.  MEASUREMENT applies
only to a declared phenomenon, measurand, uncertainty or missingness; budget
counters, combinatorial bounds, declared clock units and freshness windows are
not measurements.  CONTROLLER applies only when observed results direct a
submitted action.  ASSET applies to recorded holdings, the registry's ASSET
contract; its three obligations remain open blockers.  TRANSACTION applies only
to commit, acknowledgement or idempotency semantics, not to hash commitments.
LEDGER does not apply to verifiers of supplied history.  PROTOCOL applies to
ordered handovers, dispatch-before-emission and ack-before-dispatch ordering, or
signed statements.

Claim boundary: this is ownership and role-applicability data for the named
source bytes only.  It establishes neither mechanism truth, obligation
fulfillment, admission into the package graph, polish conformance, physical or
financial effect, release authority, nor deployment.  The GRAPH row's typed
layout and the ASSET obligations are open blockers, reported by ``open_blockers``
rather than exempted.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Literal, Mapping, NoReturn

from verifier.runtime.package_semantic_ownership_model import (
    RootRoleDecision,
    SemanticOwnershipSpec,
    ownership_spec,
    root_role_decision,
)


PRIMARY_KINDS = (
    "ENV",
    "EVENT",
    "GRAPH",
    "HYPER",
    "IDENTITY",
    "OWNER",
    "RECEIPT",
    "ROLE",
    "SPACE",
    "TIME",
)

# The twelve registered specializations of OBJECT.  Each row decides every one
# of them; a registry change must update this closed set and its tests.
ACCUMULATING_ROLES = (
    "ACTUATOR",
    "ASSET",
    "CONTROLLER",
    "FINBOT",
    "LEDGER",
    "MARKET",
    "MEASUREMENT",
    "POLICY",
    "PROTOCOL",
    "ROBOT",
    "SENSOR",
    "TRANSACTION",
)
# The only root kind decided for these rows.  Other root kinds are outside this
# batch's decision scope and are reported as unresolved rather than exempted.
ROOT_ROLE = "VERIFIER"
DECIDED_ROLES = (*ACCUMULATING_ROLES, ROOT_ROLE)

UNKNOWN_STATUS = "UNKNOWN"
STATUSES = ("APPLIES", "DOES_NOT_APPLY", UNKNOWN_STATUS)

# Operand slots required by the typed composition layout.  The rules are copied
# so validation needs no registry import; tests compare them with the real
# ``verifier.core.namespace`` layout.  GRAPH is deliberately absent: its layout
# needs aggregate-level members and a payload element kind, reported as a blocker.
REQUIRED_OPERAND_ROLES = {
    "EVENT": frozenset({"meaning", "space", "time"}),
    "IDENTITY": frozenset({"actor", "role"}),
    "OWNER": frozenset({"actor", "object"}),
    "RECEIPT": frozenset({"hardware", "subject"}),
}
ZERO_OPERAND_KINDS = frozenset({"ENV", "ROLE", "SPACE", "TIME"})
OPEN_LAYOUT_BLOCKERS = (
    "vstd-package-graph GRAPH layout: members operand and payload element_kind are "
    "aggregate-level package facts that this batch does not bind",
)
# The registry's ASSET contract names three admission obligations.  The owner rows
# record holdings under that contract, but do not discharge any of the three.
ASSET_OBLIGATION_BLOCKERS = (
    "vstd-owner ASSET obligations ASSET-0.1-identity-and-quantity, "
    "ASSET-0.2-issuance-and-redemption and ASSET-0.3-custody-and-encumbrance are "
    "unbound by this batch; recorded-holding applicability discharges none of them",
)

_OBJECT_ID = re.compile(r"[a-z][a-z0-9-]{2,95}")
_OPERAND_ROLE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_SYMBOL = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*|<module>")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_PATH_PREFIX = "src/verifier/"
_MODULE_SYMBOL = "<module>"

# Role tests are AST predicates over executable source (see the module docstring).
# ROLE_TESTS names each test's structural fact in the words the decision reasons use,
# so a DOES_NOT_APPLY reason states the fact it refuted rather than a file list.
ROLE_TESTS: Mapping[str, str] = {
    "ACTUATOR": "route-registry dispatch of a data-indexed selector, a non-constant registry mapping lookup, a dynamic getattr or import of a non-constant name, or a data-indexed subprocess or os.system call (a call with fixed arguments is not actuation)",
    "ASSET": "a recorded-holding identifier (holding, holdings, custody, redemption or issuance)",
    "CONTROLLER": "a controller identifier (controller_id, terminal_controller, submitted or directed action)",
    "FINBOT": "a finbot, trade or broker identifier",
    "LEDGER": "a debit or credit call, a ledger_append, ledger_register or ledger_write identifier, a ledger subscript, or a balance augmented assignment",
    "MARKET": "a market, price or order_book identifier",
    "MEASUREMENT": "a declared measurand token (phenomenon, measurand, uncertainty or missingness) or a latency or resource quantity (elapsed_ms, wall_seconds or memory_bytes)",
    "POLICY": "a policy admission: a _policy definition or call, a retained_selection.policy call, or a policy= keyword handoff",
    "PROTOCOL": "an ordering predicate (not in topic_of or pending), a handover or first_sequence identifier, a signature identifier, or a sequence, from, taking or leaving key",
    "ROBOT": "a robot or motor identifier",
    "SENSOR": "an acquisition call (convert, read_adc, read_channel, read_sample, sample or acquire) on a receiver",
    "TRANSACTION": "a commit call, or an acknowledgement, idempotency or rollback identifier",
    "VERIFIER": "a reference to Refuted, Unavailable, MechanismDecision or MechanismOutcome",
}

_ACQUISITION_CALLS = frozenset({"acquire", "convert", "read_adc", "read_channel", "read_sample", "sample"})
# Semantic path tokens that an acquisition must sit beside before SENSOR applies.
_ACQUISITION_PATH = re.compile(r"calibrat|^gain$|envelope|sample_rate|sampling_|fault_(mode|model|code)|dropout")
_ASSET_TOKENS = frozenset({"custody", "holding", "holdings", "issuance", "redemption"})
_CONTROLLER_TOKENS = frozenset({"controller_id", "directed_action", "submit_action", "submitted_action", "terminal_controller"})
_CONTROLLER_ACTIONS = frozenset({"directed_action", "submit_action", "submitted_action"})
_CONTROLLER_FEEDBACK = frozenset({"feedback", "observation", "observations", "observed", "result", "results"})
_DYNAMIC_IMPORT_CALLS = frozenset({"__import__", "importlib.import_module"})
_IDENTIFIER_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_LEDGER_WRITE = re.compile(r"ledger_(append|register|write)")
_MEASURAND_DECLARATION = frozenset({"measurand", "missingness", "phenomenon", "uncertainty"})
_MEASURAND_QUANTITY = frozenset({"elapsed_ms", "memory_bytes", "wall_seconds"})
_TIME_BASE_TOKENS = frozenset({"clock", "clock_id", "end", "finished_at", "instant", "start", "started_at", "time_base", "timestamp"})
_ORDERING_TARGETS = frozenset({"pending", "topic_of"})
_PROTOCOL_KEYS = frozenset({"from", "leaving", "sequence", "taking"})
_PROTOCOL_NAMES = frozenset({"first_sequence", "handover"})
_SUBPROCESS_CALLS = frozenset({"os.system", "subprocess.Popen", "subprocess.call", "subprocess.check_call",
                               "subprocess.check_output", "subprocess.run"})
_TRANSACTION_NAME = re.compile(r"acknowledg|idempot|rollback")
_VERIFIER_NAMES = frozenset({"MechanismDecision", "MechanismOutcome", "Refuted", "Unavailable"})
_BUILTIN_ERRORS = frozenset({"AssertionError", "AttributeError", "IndexError", "KeyError", "OverflowError",
                              "RecursionError", "RuntimeError", "TypeError", "UnicodeError", "ValueError"})



@dataclass(frozen=True)
class SourceCensusRow:
    """One exact candidate source file, its line count and its raw-byte digest."""

    path: str
    lines: int
    sha256: str


@dataclass(frozen=True)
class SourceEvidence:
    """One executable source span that supports a role decision."""

    path: str
    symbol: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class SourceRoleDecision:
    """APPLIES, DOES_NOT_APPLY or UNKNOWN for one role of one object, with evidence."""

    object_id: str
    role: str
    status: Literal["APPLIES", "DOES_NOT_APPLY", "UNKNOWN"]
    evidence: tuple[SourceEvidence, ...]
    reason: str


def source_digest(path: str | Path) -> str:
    """Return the raw-byte digest of one file, in the census format."""
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


@dataclass(frozen=True)
class _Scan:
    """AST facts of one source text: import aliases, dead lines and name tokens.

    A token is ``(line, kind, text)``: ``name`` for an identifier, attribute,
    definition, argument or keyword, and ``key`` for a single-token string used as a
    subscript index or dictionary key.  Prose, comments and docstrings yield no tokens.
    """

    tree: ast.Module
    aliases: Mapping[str, str]
    dead: frozenset[int]
    tokens: tuple[tuple[int, str, str], ...]


def _scan(text: str) -> _Scan:
    tree = ast.parse(text)
    return _Scan(tree, _import_aliases(tree), _dead_lines(tree), _tokens(tree))


def _import_aliases(tree: ast.Module) -> dict[str, str]:
    """Map each locally bound import name to the dotted module or member it binds."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    head = alias.name.split(".")[0]
                    aliases[head] = head
    return aliases


def _resolved(node: ast.AST, aliases: Mapping[str, str]) -> str | None:
    """Return the dotted name of an attribute chain with its head import resolved."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return ".".join([aliases.get(node.id, node.id), *reversed(parts)])


def _names(node: ast.AST) -> set[str]:
    names = {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}
    return names | {child.attr for child in ast.walk(node) if isinstance(child, ast.Attribute)}


def _key_text(node: ast.AST | None) -> str | None:
    """Return the single-token string a subscript index or dictionary key carries, or None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and _IDENTIFIER_KEY.fullmatch(node.value):
        return node.value
    return None


def _add_key(out: list[tuple[int, str, str]], node: ast.AST | None) -> None:
    text = _key_text(node)
    if node is not None and text is not None:
        out.append((node.lineno, "key", text))


def _tokens(tree: ast.Module) -> tuple[tuple[int, str, str], ...]:
    out: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            out.append((node.lineno, "name", node.id))
        elif isinstance(node, ast.Attribute):
            out.append((node.lineno, "name", node.attr))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.append((node.lineno, "name", node.name))
        elif isinstance(node, ast.arg):
            out.append((node.lineno, "name", node.arg))
        elif isinstance(node, ast.keyword) and node.arg:
            out.append((node.lineno, "name", node.arg))
        elif isinstance(node, ast.Subscript):
            _add_key(out, node.slice)
        elif isinstance(node, ast.Dict):
            for key in node.keys:
                _add_key(out, key)
        elif isinstance(node, ast.Set):
            for element in node.elts:
                _add_key(out, element)
    return tuple(out)


def _dead_lines(tree: ast.Module) -> frozenset[int]:
    """Return the lines of statements that cannot run.

    A statement after an unconditional exit in the same block is dead, and so is a
    branch whose constant test is fixed.  Dead code never establishes APPLIES.
    """
    dead: set[int] = set()

    def bury(statements: list[ast.stmt]) -> None:
        for statement in statements:
            dead.update(range(statement.lineno, (statement.end_lineno or statement.lineno) + 1))

    for node in ast.walk(tree):
        for field in ("body", "orelse", "finalbody"):
            block = getattr(node, field, None)
            if isinstance(block, list) and block and all(isinstance(item, ast.stmt) for item in block):
                for index, statement in enumerate(block):
                    if isinstance(statement, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                        bury(block[index + 1:])
                        break
        if isinstance(node, ast.If) and isinstance(node.test, ast.Constant):
            bury(node.orelse if node.test.value else node.body)
    return frozenset(dead)


def _registry_member(dotted: str | None) -> bool:
    return dotted is not None and any(dotted.startswith(module + ".") for module in _REGISTRY_MODULES)


def _data_indexed(node: ast.AST) -> bool:
    """True when the expression indexes a named value, so the selector it passes is data."""
    return any(isinstance(child, ast.Subscript) and isinstance(child.value, ast.Name)
               for child in ast.walk(node))


def _actuator_lines(scan: _Scan) -> list[int]:
    lines: list[int] = []
    for node in ast.walk(scan.tree):
        if isinstance(node, ast.Call):
            callee = _resolved(node.func, scan.aliases)
            arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
            selected = any(_data_indexed(argument) for argument in arguments)
            if _registry_member(callee) and selected:
                lines.append(node.lineno)
            elif callee in _SUBPROCESS_CALLS and selected:
                lines.append(node.lineno)
            elif callee == "getattr" and len(node.args) >= 2 and not _constant_node(node.args[1]):
                lines.append(node.lineno)
            elif callee in _DYNAMIC_IMPORT_CALLS and node.args and not _constant_node(node.args[0]):
                lines.append(node.lineno)
            elif callee is not None and _registry_member(callee) and callee.endswith("._ROUTES.get") and any(
                    not _constant_node(argument) for argument in node.args):
                lines.append(node.lineno)
        elif isinstance(node, ast.Subscript) and not _constant_node(node.slice):
            mapping = _resolved(node.value, scan.aliases)
            if mapping is not None and _registry_member(mapping) and mapping.endswith("._ROUTES"):
                lines.append(node.lineno)
    return lines


def _constant_node(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant)


def _sensor_lines(scan: _Scan) -> list[int]:
    return [node.lineno for node in ast.walk(scan.tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in _ACQUISITION_CALLS]


def _ledger_lines(scan: _Scan) -> list[int]:
    lines = [line for line, _, text in scan.tokens if _LEDGER_WRITE.match(text)]
    for node in ast.walk(scan.tree):
        if isinstance(node, ast.Call) and (_resolved(node.func, scan.aliases) or "").rsplit(".", 1)[-1] in {"credit", "debit"}:
            lines.append(node.lineno)
        elif isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == "ledger":
            lines.append(node.lineno)
        elif (isinstance(node, ast.AugAssign) and isinstance(node.op, (ast.Add, ast.Sub))
              and any("balance" in name for name in _names(node.target))):
            lines.append(node.lineno)
    return lines


def _policy_lines(scan: _Scan) -> list[int]:
    lines: list[int] = []
    for node in ast.walk(scan.tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "_policy":
            lines.append(node.lineno)
        elif isinstance(node, ast.Call):
            callee = _resolved(node.func, scan.aliases) or ""
            if callee == "_policy" or callee.endswith("._policy") or callee.endswith("retained_selection.policy"):
                lines.append(node.lineno)
            if any(keyword.arg == "policy" for keyword in node.keywords):
                lines.append(node.lineno)
    return lines


def _protocol_lines(scan: _Scan) -> list[int]:
    lines = [line for line, kind, text in scan.tokens
             if text in _PROTOCOL_NAMES or "signature" in text
             or (kind == "key" and text in _PROTOCOL_KEYS and text != "from")]
    lines += [line for line, kind, text in scan.tokens
              if kind == "key" and text == "from" and _enclosing_names(scan, line) & {"event", "events"}]
    for node in ast.walk(scan.tree):
        if (isinstance(node, ast.Compare) and any(isinstance(op, ast.NotIn) for op in node.ops)
                and any(isinstance(item, ast.Name) and item.id in _ORDERING_TARGETS for item in node.comparators)):
            lines.append(node.lineno)
    return lines


def _verifier_lines(scan: _Scan) -> list[int]:
    """Lines that refuse or report a verdict: a raise of a verdict error class."""
    lines: list[int] = []
    for node in ast.walk(scan.tree):
        if isinstance(node, ast.Raise) and node.exc is not None:
            target = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
            last = (_resolved(target, scan.aliases) or "").rsplit(".", 1)[-1]
            if last not in _BUILTIN_ERRORS and (last.endswith(("Error", "Unavailable", "Refuted")) or last in _VERIFIER_NAMES):
                lines.append(node.lineno)
        elif isinstance(node, ast.Name) and node.id in _VERIFIER_NAMES:
            lines.append(node.lineno)
    return lines


def _enclosing_names(scan: _Scan, line: int) -> set[str]:
    """Return the names of the innermost function that contains a line, or of the module."""
    scope: ast.AST = scan.tree
    for node in ast.walk(scan.tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= line <= (node.end_lineno or node.lineno):
            if isinstance(scope, ast.Module) or (node.end_lineno or 0) - node.lineno < (scope.end_lineno or 0) - scope.lineno:
                scope = node
    return {child.id for child in ast.walk(scope) if isinstance(child, ast.Name)}


def _transaction_lines(scan: _Scan) -> list[int]:
    lines = [line for line, _, text in scan.tokens if _TRANSACTION_NAME.search(text)]
    for node in ast.walk(scan.tree):
        if isinstance(node, ast.Call) and (_resolved(node.func, scan.aliases) or "").rsplit(".", 1)[-1] == "commit":
            lines.append(node.lineno)
    return lines


def _role_lines(role: str, scan: _Scan) -> list[int]:
    """Return every line whose AST carries the role's test, dead or live."""
    if role == "ACTUATOR":
        return _actuator_lines(scan)
    if role == "SENSOR":
        return _sensor_lines(scan)
    if role == "LEDGER":
        return _ledger_lines(scan)
    if role == "POLICY":
        return _policy_lines(scan)
    if role == "PROTOCOL":
        return _protocol_lines(scan)
    if role == "TRANSACTION":
        return _transaction_lines(scan)
    if role == "VERIFIER":
        return _verifier_lines(scan)
    tokens = {
        "ASSET": lambda text: text in _ASSET_TOKENS,
        "CONTROLLER": lambda text: text in _CONTROLLER_TOKENS,
        "FINBOT": lambda text: "finbot" in text or text in {"broker", "trade"},
        "MARKET": lambda text: text.startswith(("market", "order_book")) or text == "price",
        "MEASUREMENT": lambda text: text in _MEASURAND_DECLARATION or text in _MEASURAND_QUANTITY,
        "ROBOT": lambda text: "robot" in text or text == "motor" or text.startswith("motor_"),
    }
    if role not in tokens:
        raise ValueError(f"no AST test for role {role}")
    return [line for line, _, text in scan.tokens if tokens[role](text)]


def _hits(role: str, scan: _Scan) -> tuple[int, ...]:
    return tuple(sorted(set(_role_lines(role, scan))))


def _span_tokens(scan: _Scan, start: int, end: int) -> frozenset[str]:
    return frozenset(text for line, _, text in scan.tokens if start <= line <= end)


def _requirement_gap(role: str, tokens: frozenset[str]) -> str | None:
    """Return the APPLIES requirement a span lacks, or None when it carries all of them."""
    if role == "SENSOR" and not any(_ACQUISITION_PATH.search(text) for text in tokens):
        return "a calibration, gain, envelope, sampling or fault path beside the acquisition call"
    if role == "MEASUREMENT" and not (
            "phenomenon" in tokens and tokens & {"unit", "units"}
            and tokens & {"method", "instrument"} and tokens & {"missingness", "uncertainty"}):
        return "a declared phenomenon with units, a method, and uncertainty or missingness"
    if role == "MEASUREMENT" and tokens & {"elapsed_ms", "wall_seconds"} and not tokens & _TIME_BASE_TOKENS:
        return "a declared time base for the latency quantity"
    if role == "CONTROLLER" and not (tokens & _CONTROLLER_ACTIONS and tokens & _CONTROLLER_FEEDBACK):
        return "a submitted or directed action fed by an observed result"
    return None


def gate_hits(role: str, text: str) -> tuple[int, ...]:
    """Return the executable and dead line numbers of one source text that carry a role test."""
    return _hits(role, _scan(text))


def _code_lines(text: str) -> dict[int, str]:
    """Return executable line numbers, excluding docstrings and comment lines."""
    tree = ast.parse(text)
    doc: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                first = body[0]
                doc.update(range(first.lineno, (first.end_lineno or first.lineno) + 1))
    lines = text.splitlines()
    return {
        number: line
        for number, line in enumerate(lines, 1)
        if number not in doc and not line.lstrip().startswith("#")
    }



# Exact candidate census: the 41 root-admitted source files of these ten rows.
# Line counts and digests are the raw-byte values of the files as currently
# present in the shared tree; drift is detected by ``source_drift_failures``.
_CENSUS_ROWS = (
    ("src/verifier/domains/contracts/env_checks.py", 301, "sha256:3f653ffcf352eeb22a803a416369243e0e14ad271d97679c9613fc57fe74b79b"),
    ("src/verifier/domains/contracts/env_checks_projection.py", 146, "sha256:436d2b6587198433ec6b55e20204b23e62750a484c8f0eec911f0280bcf614a3"),
    ("src/verifier/domains/contracts/env_configuration_surface.py", 604, "sha256:330dd5e4ab2332507bf922cb1da203206df9c2ed4b19673740b58badf4a45828"),
    ("src/verifier/domains/contracts/env_executable.py", 474, "sha256:a17e1150a2d7e6b1c0ed579c7897cb7096880090a4158d25a9ef34bd0883cdc5"),
    ("src/verifier/domains/contracts/env_pin_closure.py", 513, "sha256:7ae0f9fce22895cd8b4805dcd05fbeaf0fe9995f97a88aaba40501dc99de63c8"),
    ("src/verifier/domains/contracts/event_closure.py", 398, "sha256:38a0a3096428aedd25a41052fe5cd79e02840592193953ebfc25cdd6b2428e22"),
    ("src/verifier/domains/contracts/event_dispatch.py", 462, "sha256:24cd36064b8638b1c43dc55671085e4ce1637939245d24fb5e2430c081f066c7"),
    ("src/verifier/domains/contracts/event_prerequisites.py", 398, "sha256:9225d0d289c1eb39bf725d7ad74ac6b7fc39ab92576cba1426135a1c9a633d35"),
    ("src/verifier/domains/contracts/graph_closure.py", 422, "sha256:0c7e109c21e116bd0a690b2a8a55d7eb3af7c3b0737f0ae4ee1361f0cdeaf53f"),
    ("src/verifier/domains/contracts/graph_lineage.py", 456, "sha256:ac34d79a1c6bc373127367aee2a3a8c52da9e11a00aa81a759125fcd12c1e5d6"),
    ("src/verifier/domains/contracts/graph_order.py", 419, "sha256:bc09356496bb7c297c95251c12a650a56e106d61cd22726c7716f80d27e6d4b4"),
    ("src/verifier/domains/contracts/graph_statics.py", 446, "sha256:a7d3c45a2ab99fb5659ee33ac3c9a227d6a2cd242b984caa1439d5ff2b83684e"),
    ("src/verifier/domains/contracts/hyper_closure.py", 467, "sha256:90dd531363322e219ca087998c6dac75a5f9793ed87902b66fa2719fba023053"),
    ("src/verifier/domains/contracts/hyper_composed_ceiling.py", 328, "sha256:3001f4576c0f4a0aa0d51fcaa9c2c19c68dc3c490feb124415e5237d91470efb"),
    ("src/verifier/domains/contracts/hyper_unknown_absorption.py", 484, "sha256:7fcadd2d7ddc563c983918e4a910d3d2ca4645920b384d396987772bbcffb8d5"),
    ("src/verifier/domains/contracts/identity_lifecycle.py", 558, "sha256:efe8cf8b8d1cbc53cd272f66748794428c9c14b0e855287ea289dea9196e19db"),
    ("src/verifier/domains/contracts/identity_lifecycle_replay.py", 540, "sha256:67005d9834fb56747734566f36a396356e0c94e62d474528bee719c258aeb114"),
    ("src/verifier/domains/contracts/identity_occupancy.py", 232, "sha256:3c0cf401b5872766a5d6f7a86914a5036a364929c16f1d3adbf5f843cfa24bb4"),
    ("src/verifier/domains/contracts/identity_presentation.py", 1056, "sha256:f5000fc720bd22e17276f398bef57c3b37dbf42c301a9698f534d64e7446f289"),
    ("src/verifier/domains/contracts/identity_scope.py", 301, "sha256:18aa50004e19a84be846de21e7d7ddc71c8f80470a6c6774393e9f35257ee14d"),
    ("src/verifier/domains/contracts/owner_eligibility.py", 345, "sha256:6d84fe13dd2957be14b9ed1065c36d762479d81bd74f0a976abfdda16401d8c9"),
    ("src/verifier/domains/contracts/owner_forks.py", 576, "sha256:e9bd7f4809c8968317bec45f871c0b62f694f39935051ecd892c57a8df6f0ebf"),
    ("src/verifier/domains/contracts/owner_replay.py", 583, "sha256:81a9087d24750a3f922b1dbca63466c5ea0de1af4a14e7a3cd272ba7771a012e"),
    ("src/verifier/domains/contracts/receipt_authenticity.py", 395, "sha256:e2edec1d13aca987ba0b59a3d7ecdb5550a0006a3ffbf74d09fa222b4a6fdc69"),
    ("src/verifier/domains/contracts/receipt_chain.py", 390, "sha256:7ea7ffaa618570cf7b53366f80cb03b2665cd440b3d3b28aee9772586437048f"),
    ("src/verifier/domains/contracts/receipt_prerequisite_closure.py", 425, "sha256:6c7179476d37091a936e2f824e560905d1d1123073b0ee73d0d6c3b5a396f175"),
    ("src/verifier/domains/contracts/receipt_statics.py", 581, "sha256:f14ea956678b061ba5f80c683b361820da0821adb9571f56455c0e6717869b98"),
    ("src/verifier/domains/contracts/receipt_validation_replay.py", 368, "sha256:e9fbff52f11102ede40f71cfbc4150d77127c167d3bace263e8c8207388feb25"),
    ("src/verifier/domains/contracts/role_closure.py", 523, "sha256:4bfda2338fee3651b38a4816bfd902733caa2ff3d9d25a630ecf3792872ce8e3"),
    ("src/verifier/domains/contracts/role_constraints.py", 495, "sha256:0ac9f2a90e671b27742b68e2c2a850c27b618c6eead37c3071c1c19dd2ae77af"),
    ("src/verifier/domains/contracts/role_lifecycle.py", 505, "sha256:10ea426c28e841431f5ff195afa9a9d806e955d89ca2977e57f350c214897921"),
    ("src/verifier/domains/contracts/space_closure.py", 359, "sha256:d19cb928df95d39ff2c1b59042ea24ba3f24b70ce40901ab502e1ff6a50dc479"),
    ("src/verifier/domains/contracts/space_layout.py", 385, "sha256:b18a5237d8ff18ba5ac11ddd387409d868dc73b5a472c97387f9b919830d6094"),
    ("src/verifier/domains/contracts/space_migration.py", 410, "sha256:cb07041da80cd072e8b7f7dc500205a994487c8c6b19abd07cb6d05a5cd9a1ab"),
    ("src/verifier/domains/contracts/time_closure.py", 575, "sha256:cf0292125c35306864f529e2c9a86b126efd8aab1516ede64d661c70e023084a"),
    ("src/verifier/domains/contracts/time_order.py", 381, "sha256:8f9260a61954a4b3c56fff5e9a1a87ad4a6db767bdf1db85b26fc327d5476441"),
    ("src/verifier/domains/contracts/time_strict.py", 364, "sha256:557a7e3af5b4c3dba6d64036159e0de528d06ec648c6542359cd39b75d63d205"),
    ("src/verifier/domains/env.py", 68, "sha256:8c837bb8e11f41da13db4deaf2a71394b9e802b7fde1bed51d6a8cdab1264e95"),
    ("src/verifier/domains/identity.py", 171, "sha256:7e1789b4c952c487caafe26698c9c88b977a9c4dee8101c43f2bf91ec143a329"),
    ("src/verifier/domains/owner.py", 150, "sha256:358f5560f0b79554dcb904fdb5af1d568a5f271436dc6da73e95138e240ce22a"),
    ("src/verifier/domains/role.py", 83, "sha256:d45ebd8a434ce53ec21ddd0c13c7583952c099e5d0dd71e7a82a6a25bbb92355"),
)

DOMAIN_CONTEXT_SOURCE_CENSUS: tuple[SourceCensusRow, ...] = tuple(
    SourceCensusRow(path, lines, sha256) for path, lines, sha256 in _CENSUS_ROWS
)
DOMAIN_CONTEXT_PATH_CENSUS: tuple[str, ...] = tuple(row.path for row in DOMAIN_CONTEXT_SOURCE_CENSUS)
DOMAIN_CONTEXT_SOURCE_DIGESTS: Mapping[str, str] = {
    row.path: row.sha256 for row in DOMAIN_CONTEXT_SOURCE_CENSUS
}
_LINE_COUNTS: Mapping[str, int] = {row.path: row.lines for row in DOMAIN_CONTEXT_SOURCE_CENSUS}

# Verifier modules imported by the owned files that are outside the census.  Each is
# declared with its boundary class and reason.  A ROUTE_REGISTRY dependency is a
# closed registry that owned code dispatches through or binds as catalog evidence;
# this batch does not decide its own semantics.
EXTERNAL_EVIDENCE_DEPENDENCIES: Mapping[str, tuple[str, str]] = {
    "verifier.core.certificate": ("CORE_LIBRARY", "canonical bytes and digests bound into owned certificates"),
    "verifier.core.checker": ("SOURCE_BINDING", "checker module file digest is bound as implementation_hash in receipt certificates, and its auditor and constants are imported by receipt checkers"),
    "verifier.core.evidence": ("CORE_LIBRARY", "evidence store and mechanism decision types used by owned checkers"),
    "verifier.core.namespace": ("CORE_LIBRARY", "namespace object digests and typed layout used by owned checkers"),
    "verifier.core.provenance": ("CORE_LIBRARY", "provenance record types that receipt payloads are parsed into"),
    "verifier.core.receipt": ("CORE_LIBRARY", "strict JSON loading of retained evidence"),
    "verifier.core.signature_keys": ("CORE_LIBRARY", "Ed25519 public key admission primitive used by signature checks"),
    "verifier.domains.common": ("CORE_LIBRARY", "bounded budget and Refuted or Unavailable outcomes"),
    "verifier.domains.contracts.accountability": ("EVIDENCE_PRODUCER", "accountability.assess_hardware_ownership produces the verdict that owner eligibility consumes"),
    "verifier.domains.contracts.current_object_routes": ("ROUTE_REGISTRY", "closed route registry: hyper_unknown_absorption dispatches a data-chosen objective through it (ACTUATOR evidence), and env_checks_projection binds its source file digest as route_catalog evidence"),
    "verifier.domains.contracts.retained_selection": ("EVIDENCE_SELECTION", "selects retained evidence records consumed by owned checkers"),
    "verifier.domains.contracts.sim_isolation": ("SOURCE_BINDING", "module imported only into the installed-source digest tuple of owner eligibility; it supplies no verdict"),
    "verifier.domains.contracts.typed_facets": ("EVIDENCE_SELECTION", "typed facet records consumed by owned environment checkers"),
}

# Named symbol spans recorded from the source's AST.  Each entry is checked
# against the current file by ``evidence_failures``; a moved span is stale.
_SPANS = {
    ("src/verifier/domains/contracts/env_checks.py", "_policy"): (115, 130),
    ("src/verifier/domains/contracts/env_checks.py", "mechanism_digest"): (106, 112),
    ("src/verifier/domains/contracts/env_checks.py", "recheck_env_checks_certificate"): (275, 296),
    ("src/verifier/domains/contracts/env_checks_projection.py", "accepted_projection"): (84, 96),
    ("src/verifier/domains/contracts/env_checks_projection.py", "installed_source_bindings"): (69, 81),
    ("src/verifier/domains/contracts/env_checks_projection.py", "project_registration"): (99, 140),
    ("src/verifier/domains/contracts/env_configuration_surface.py", "_evaluate"): (419, 487),
    ("src/verifier/domains/contracts/env_configuration_surface.py", "mechanism_digest"): (95, 110),
    ("src/verifier/domains/contracts/env_configuration_surface.py", "recheck_env_configuration_surface_certificate"): (563, 595),
    ("src/verifier/domains/contracts/env_executable.py", "_evaluate"): (282, 358),
    ("src/verifier/domains/contracts/env_executable.py", "mechanism_digest"): (90, 104),
    ("src/verifier/domains/contracts/env_executable.py", "recheck_env_executable_certificate"): (434, 466),
    ("src/verifier/domains/contracts/env_pin_closure.py", "_evaluate"): (304, 398),
    ("src/verifier/domains/contracts/env_pin_closure.py", "mechanism_digest"): (91, 106),
    ("src/verifier/domains/contracts/env_pin_closure.py", "recheck_env_pin_closure_certificate"): (473, 505),
    ("src/verifier/domains/contracts/event_closure.py", "_evaluate"): (197, 281),
    ("src/verifier/domains/contracts/event_closure.py", "mechanism_digest"): (95, 106),
    ("src/verifier/domains/contracts/event_closure.py", "recheck_event_closure_certificate"): (361, 391),
    ("src/verifier/domains/contracts/event_dispatch.py", "_replay_log"): (225, 286),
    ("src/verifier/domains/contracts/event_dispatch.py", "mechanism_digest"): (109, 121),
    ("src/verifier/domains/contracts/event_dispatch.py", "recheck_event_dispatch_certificate"): (423, 453),
    ("src/verifier/domains/contracts/event_prerequisites.py", "_evaluate"): (182, 282),
    ("src/verifier/domains/contracts/event_prerequisites.py", "mechanism_digest"): (100, 112),
    ("src/verifier/domains/contracts/event_prerequisites.py", "recheck_event_prerequisites_certificate"): (359, 389),
    ("src/verifier/domains/contracts/graph_closure.py", "_declared_rows"): (221, 247),
    ("src/verifier/domains/contracts/graph_closure.py", "mechanism_digest"): (89, 99),
    ("src/verifier/domains/contracts/graph_closure.py", "recheck_graph_closure_certificate"): (385, 415),
    ("src/verifier/domains/contracts/graph_lineage.py", "_child_status"): (196, 230),
    ("src/verifier/domains/contracts/graph_lineage.py", "mechanism_digest"): (104, 114),
    ("src/verifier/domains/contracts/graph_lineage.py", "recheck_graph_lineage_certificate"): (421, 450),
    ("src/verifier/domains/contracts/graph_order.py", "_evaluate"): (265, 305),
    ("src/verifier/domains/contracts/graph_order.py", "mechanism_digest"): (89, 99),
    ("src/verifier/domains/contracts/graph_order.py", "recheck_graph_order_certificate"): (382, 412),
    ("src/verifier/domains/contracts/graph_statics.py", "_policy"): (128, 150),
    ("src/verifier/domains/contracts/graph_statics.py", "mechanism_digest"): (113, 125),
    ("src/verifier/domains/contracts/graph_statics.py", "recheck_graph_statics_certificate"): (407, 437),
    ("src/verifier/domains/contracts/hyper_closure.py", "_policy"): (147, 166),
    ("src/verifier/domains/contracts/hyper_closure.py", "mechanism_digest"): (120, 134),
    ("src/verifier/domains/contracts/hyper_closure.py", "recheck_hyper_closure_certificate"): (424, 461),
    ("src/verifier/domains/contracts/hyper_composed_ceiling.py", "_evaluate"): (166, 209),
    ("src/verifier/domains/contracts/hyper_composed_ceiling.py", "_policy"): (104, 108),
    ("src/verifier/domains/contracts/hyper_composed_ceiling.py", "mechanism_digest"): (93, 101),
    ("src/verifier/domains/contracts/hyper_composed_ceiling.py", "recheck_hyper_composed_ceiling_certificate"): (288, 319),
    ("src/verifier/domains/contracts/hyper_unknown_absorption.py", "bound_children"): (249, 325),
    ("src/verifier/domains/contracts/hyper_unknown_absorption.py", "dependency_paths"): (99, 109),
    ("src/verifier/domains/contracts/hyper_unknown_absorption.py", "recheck_hyper_unknown_absorption_certificate"): (444, 475),
    ("src/verifier/domains/contracts/hyper_unknown_absorption.py", "select_children"): (132, 162),
    ("src/verifier/domains/contracts/identity_lifecycle.py", "_policy"): (208, 229),
    ("src/verifier/domains/contracts/identity_lifecycle.py", "mechanism_digest"): (196, 205),
    ("src/verifier/domains/contracts/identity_lifecycle.py", "recheck_identity_lifecycle_certificate"): (513, 551),
    ("src/verifier/domains/contracts/identity_lifecycle_replay.py", "replay_declared_identity_lifecycle"): (122, 540),
    ("src/verifier/domains/contracts/identity_occupancy.py", "assess_identity_occupancy"): (63, 201),
    ("src/verifier/domains/contracts/identity_occupancy.py", "recheck_identity_occupancy"): (204, 232),
    ("src/verifier/domains/contracts/identity_presentation.py", "_evaluate"): (714, 909),
    ("src/verifier/domains/contracts/identity_presentation.py", "_exit_probe"): (553, 611),
    ("src/verifier/domains/contracts/identity_presentation.py", "_policy"): (213, 277),
    ("src/verifier/domains/contracts/identity_presentation.py", "_support"): (415, 550),
    ("src/verifier/domains/contracts/identity_presentation.py", "_verify_signature"): (384, 398),
    ("src/verifier/domains/contracts/identity_presentation.py", "mechanism_digest"): (200, 210),
    ("src/verifier/domains/contracts/identity_presentation.py", "recheck_identity_presentation_certificate"): (1016, 1050),
    ("src/verifier/domains/contracts/identity_scope.py", "_policy"): (81, 96),
    ("src/verifier/domains/contracts/identity_scope.py", "mechanism_digest"): (72, 78),
    ("src/verifier/domains/contracts/identity_scope.py", "recheck_identity_scope_certificate"): (265, 296),
    ("src/verifier/domains/contracts/owner_eligibility.py", "_evaluate"): (203, 245),
    ("src/verifier/domains/contracts/owner_eligibility.py", "_policy"): (107, 110),
    ("src/verifier/domains/contracts/owner_eligibility.py", "mechanism_digest"): (95, 104),
    ("src/verifier/domains/contracts/owner_eligibility.py", "recheck_owner_eligibility_certificate"): (313, 339),
    ("src/verifier/domains/contracts/owner_forks.py", "_detect"): (368, 402),
    ("src/verifier/domains/contracts/owner_forks.py", "mechanism_digest"): (118, 127),
    ("src/verifier/domains/contracts/owner_forks.py", "recheck_owner_forks_certificate"): (539, 569),
    ("src/verifier/domains/contracts/owner_replay.py", "_replay"): (313, 410),
    ("src/verifier/domains/contracts/owner_replay.py", "mechanism_digest"): (122, 131),
    ("src/verifier/domains/contracts/owner_replay.py", "recheck_owner_replay_certificate"): (546, 576),
    ("src/verifier/domains/contracts/receipt_authenticity.py", "_evaluate"): (244, 293),
    ("src/verifier/domains/contracts/receipt_authenticity.py", "_policy"): (108, 133),
    ("src/verifier/domains/contracts/receipt_authenticity.py", "mechanism_digest"): (75, 85),
    ("src/verifier/domains/contracts/receipt_authenticity.py", "recheck_receipt_authenticity_certificate"): (349, 395),
    ("src/verifier/domains/contracts/receipt_chain.py", "_policy"): (110, 128),
    ("src/verifier/domains/contracts/receipt_chain.py", "mechanism_digest"): (95, 107),
    ("src/verifier/domains/contracts/receipt_chain.py", "recheck_receipt_chain_certificate"): (343, 384),
    ("src/verifier/domains/contracts/receipt_prerequisite_closure.py", "_evaluate"): (274, 303),
    ("src/verifier/domains/contracts/receipt_prerequisite_closure.py", "mechanism_digest"): (91, 102),
    ("src/verifier/domains/contracts/receipt_prerequisite_closure.py", "recheck_receipt_prerequisite_closure_certificate"): (385, 417),
    ("src/verifier/domains/contracts/receipt_statics.py", "check_receipt_statics"): (392, 430),
    ("src/verifier/domains/contracts/receipt_statics.py", "mechanism_digest"): (106, 115),
    ("src/verifier/domains/contracts/receipt_statics.py", "recheck_receipt_statics_certificate"): (542, 573),
    ("src/verifier/domains/contracts/receipt_validation_replay.py", "_evaluate"): (199, 245),
    ("src/verifier/domains/contracts/receipt_validation_replay.py", "_installed_tcb"): (169, 180),
    ("src/verifier/domains/contracts/receipt_validation_replay.py", "_search_bound"): (183, 192),
    ("src/verifier/domains/contracts/receipt_validation_replay.py", "recheck_receipt_validation_replay_certificate"): (328, 360),
    ("src/verifier/domains/contracts/role_closure.py", "_evaluate"): (316, 424),
    ("src/verifier/domains/contracts/role_closure.py", "mechanism_digest"): (96, 104),
    ("src/verifier/domains/contracts/role_closure.py", "recheck_role_closure_certificate"): (487, 519),
    ("src/verifier/domains/contracts/role_constraints.py", "_evaluate"): (236, 391),
    ("src/verifier/domains/contracts/role_constraints.py", "mechanism_digest"): (109, 120),
    ("src/verifier/domains/contracts/role_constraints.py", "recheck_role_constraints_certificate"): (456, 488),
    ("src/verifier/domains/contracts/role_lifecycle.py", "_evaluate"): (290, 407),
    ("src/verifier/domains/contracts/role_lifecycle.py", "mechanism_digest"): (107, 117),
    ("src/verifier/domains/contracts/role_lifecycle.py", "recheck_role_lifecycle_certificate"): (470, 499),
    ("src/verifier/domains/contracts/space_closure.py", "_evaluate"): (175, 245),
    ("src/verifier/domains/contracts/space_closure.py", "mechanism_digest"): (80, 90),
    ("src/verifier/domains/contracts/space_closure.py", "recheck_space_closure_certificate"): (322, 352),
    ("src/verifier/domains/contracts/space_layout.py", "_evaluate"): (182, 269),
    ("src/verifier/domains/contracts/space_layout.py", "_policy"): (115, 120),
    ("src/verifier/domains/contracts/space_layout.py", "mechanism_digest"): (100, 112),
    ("src/verifier/domains/contracts/space_layout.py", "recheck_space_layout_certificate"): (346, 376),
    ("src/verifier/domains/contracts/space_migration.py", "_evaluate"): (232, 295),
    ("src/verifier/domains/contracts/space_migration.py", "mechanism_digest"): (87, 97),
    ("src/verifier/domains/contracts/space_migration.py", "recheck_space_migration_certificate"): (373, 403),
    ("src/verifier/domains/contracts/time_closure.py", "_evaluate"): (415, 456),
    ("src/verifier/domains/contracts/time_closure.py", "_policy"): (107, 115),
    ("src/verifier/domains/contracts/time_closure.py", "mechanism_digest"): (94, 104),
    ("src/verifier/domains/contracts/time_closure.py", "recheck_time_closure_certificate"): (535, 568),
    ("src/verifier/domains/contracts/time_order.py", "_evaluate"): (186, 263),
    ("src/verifier/domains/contracts/time_order.py", "mechanism_digest"): (104, 116),
    ("src/verifier/domains/contracts/time_order.py", "recheck_time_order_certificate"): (340, 372),
    ("src/verifier/domains/contracts/time_strict.py", "_evaluate"): (180, 241),
    ("src/verifier/domains/contracts/time_strict.py", "mechanism_digest"): (85, 95),
    ("src/verifier/domains/contracts/time_strict.py", "recheck_time_strict_certificate"): (327, 357),
    ("src/verifier/domains/env.py", "collect_configuration"): (9, 13),
    ("src/verifier/domains/env.py", "evaluate"): (16, 68),
    ("src/verifier/domains/identity.py", "evaluate"): (77, 171),
    ("src/verifier/domains/owner.py", "evaluate"): (34, 150),
    ("src/verifier/domains/role.py", "evaluate"): (35, 83),
    ("src/verifier/domains/contracts/receipt_statics.py", "_execution"): (347, 357),
    ("src/verifier/domains/contracts/role_constraints.py", "_policy"): (123, 126),
}


def _verifier_decision(reason: str) -> RootRoleDecision:
    """Return the VERIFIER root decision carried by every row of this batch."""
    return root_role_decision(ROOT_ROLE, "APPLIES", reason)


# Ownership rows.  Each row is one path-disjoint object; together they cover the
# census exactly.  The specializations are exactly the APPLIES accumulating roles
# in the decision table below.  GRAPH carries no operands: its layout is blocked.
DOMAIN_CONTEXT_OWNERSHIP_SPECS: tuple[SemanticOwnershipSpec, ...] = (
    ownership_spec(
        "vstd-environment",
        "ENV",
        (
            "src/verifier/domains/contracts/env_checks.py",
            "src/verifier/domains/contracts/env_checks_projection.py",
            "src/verifier/domains/contracts/env_configuration_surface.py",
            "src/verifier/domains/contracts/env_executable.py",
            "src/verifier/domains/contracts/env_pin_closure.py",
            "src/verifier/domains/env.py",
        ),
        "declared-execution-environment-checks",
        "Each ENV check replays retained process observations, configuration and installed mechanism bytes under explicit resource and allowlist policy, so the policy role must not hide inside a generic ENV owner.",
        "The checks compare retained or supplied observations; collect_configuration reads host platform identity only and establishes no sandbox, live execution, or deployment fact.",
        "POLICY",
        root_role_decisions=(_verifier_decision("env_checks.py recheck_env_checks_certificate re-derives retained environment certificates"),),
    ),
    ownership_spec(
        "vstd-event",
        "EVENT",
        (
            "src/verifier/domains/contracts/event_closure.py",
            "src/verifier/domains/contracts/event_dispatch.py",
            "src/verifier/domains/contracts/event_prerequisites.py",
        ),
        "declared-event-ordering-and-dispatch-checks",
        "Event dispatch replays ordered handovers over supplied timed events: dispatch must follow emission and acknowledgment must follow dispatch (PROTOCOL), and an acknowledged dispatch is the commit semantics (TRANSACTION).",
        "Checks replay retained event logs and installed source bytes; they do not execute events, deliver messages, or establish a live transaction.",
        "POLICY",
        "PROTOCOL",
        "TRANSACTION",
        operands=(
            ("meaning", ("vstd-package-object",)),
            ("space", ("vstd-space",)),
            ("time", ("vstd-time",)),
        ),
        root_role_decisions=(_verifier_decision("event_dispatch.py recheck_event_dispatch_certificate re-derives retained dispatch certificates"),),
    ),
    ownership_spec(
        "vstd-package-graph",
        "GRAPH",
        (
            "src/verifier/domains/contracts/graph_closure.py",
            "src/verifier/domains/contracts/graph_lineage.py",
            "src/verifier/domains/contracts/graph_order.py",
            "src/verifier/domains/contracts/graph_statics.py",
        ),
        "declared-package-graph-closure-and-order-checks",
        "Graph closure, lineage, order and statics check declared package membership and topological order; these are graph facts, not a single generic owner.",
        "Checks bind retained declarations and installed source bytes; they admit no member and assert no package publication.",
        "POLICY",
        root_role_decisions=(_verifier_decision("graph_closure.py recheck_graph_closure_certificate re-derives retained graph certificates"),),
    ),
    ownership_spec(
        "vstd-hypergraph",
        "HYPER",
        (
            "src/verifier/domains/contracts/hyper_closure.py",
            "src/verifier/domains/contracts/hyper_composed_ceiling.py",
            "src/verifier/domains/contracts/hyper_unknown_absorption.py",
        ),
        "declared-hypergraph-composition-and-ceiling-checks",
        "Hypergraph closure, composed ceiling and unknown absorption compose retained tier results; unknown absorption dispatches a data-chosen objective through a route registry, so ACTUATOR applies, while the composed ceiling is a combinatorial bound and not a measurement.",
        "Unknown absorption dispatches a data-chosen objective through the external current_object_routes registry (declared, not census-owned); the composed ceiling is a verdict input, not an admitted capacity.",
        "ACTUATOR",
        "POLICY",
        operands=(("subjects", ("vstd-package-object", "verifier-core-self")),),
        root_role_decisions=(_verifier_decision("hyper_closure.py recheck_hyper_closure_certificate re-derives retained hypergraph certificates"),),
    ),
    ownership_spec(
        "vstd-identity",
        "IDENTITY",
        (
            "src/verifier/domains/identity.py",
            "src/verifier/domains/contracts/identity_lifecycle.py",
            "src/verifier/domains/contracts/identity_lifecycle_replay.py",
            "src/verifier/domains/contracts/identity_occupancy.py",
            "src/verifier/domains/contracts/identity_presentation.py",
            "src/verifier/domains/contracts/identity_scope.py",
        ),
        "declared-identity-lifecycle-presentation-and-scope-checks",
        "Identity lifecycle, presentation and scope check retained actor and role claims under declared policy; presentation signatures are PROTOCOL statements, occupancy is a bounded count, and the holder-signed terminal transition is an unresolved CONTROLLER question.",
        "Checks verify retained signed statements and bounded occupancy; they authenticate no human and assert no live identity.",
        "POLICY",
        "PROTOCOL",
        operands=(
            ("actor", ("vstd-actor",)),
            ("role", ("vstd-role",)),
        ),
        root_role_decisions=(_verifier_decision("identity_lifecycle.py recheck_identity_lifecycle_certificate re-derives retained identity certificates"),),
    ),
    ownership_spec(
        "vstd-space",
        "SPACE",
        (
            "src/verifier/domains/contracts/space_closure.py",
            "src/verifier/domains/contracts/space_layout.py",
            "src/verifier/domains/contracts/space_migration.py",
        ),
        "declared-space-layout-closure-and-migration-checks",
        "Space closure, layout and migration check declared spatial layout under policy; their comparisons are layout and budget bounds, not derived magnitudes.",
        "Checks bind retained layouts and installed source bytes; they establish no physical space, geometry, or deployment fact.",
        "POLICY",
        root_role_decisions=(_verifier_decision("space_closure.py recheck_space_closure_certificate re-derives retained space certificates"),),
    ),
    ownership_spec(
        "vstd-time",
        "TIME",
        (
            "src/verifier/domains/contracts/time_closure.py",
            "src/verifier/domains/contracts/time_order.py",
            "src/verifier/domains/contracts/time_strict.py",
        ),
        "declared-time-order-and-closure-checks",
        "Time closure, order and strict checks declare ordering and closure of timestamps under policy; they bind retained declared time and installed source bytes.",
        "Checks do not read a live clock and do not establish that any timestamp reflects real time.",
        "POLICY",
        root_role_decisions=(_verifier_decision("time_order.py recheck_time_order_certificate re-derives retained time certificates"),),
    ),
    ownership_spec(
        "vstd-role",
        "ROLE",
        (
            "src/verifier/domains/role.py",
            "src/verifier/domains/contracts/role_closure.py",
            "src/verifier/domains/contracts/role_constraints.py",
            "src/verifier/domains/contracts/role_lifecycle.py",
        ),
        "declared-role-lifecycle-and-closure-checks",
        "Role closure and lifecycle check ordered take, leave and handover events over declared roles under policy; these are protocol facts over supplied events.",
        "Checks replay supplied decisions and bind installed source bytes; they grant no role, permission or live authority.",
        "POLICY",
        "PROTOCOL",
        root_role_decisions=(_verifier_decision("role_closure.py recheck_role_closure_certificate re-derives retained role certificates"),),
    ),
    ownership_spec(
        "vstd-owner",
        "OWNER",
        (
            "src/verifier/domains/owner.py",
            "src/verifier/domains/contracts/owner_eligibility.py",
            "src/verifier/domains/contracts/owner_forks.py",
            "src/verifier/domains/contracts/owner_replay.py",
        ),
        "declared-owner-eligibility-fork-and-replay-checks",
        "Owner eligibility, forks and replay check declared owner actor and object claims, ordered owner replays and fork detection under policy; recorded holdings fall under the registry's ASSET contract, whose three obligations remain unbound.",
        "Checks replay supplied owner records and bind installed source bytes; they establish no legal, asset or custody ownership, and ASSET applicability records only the recorded-holding contract.",
        "ASSET",
        "POLICY",
        "PROTOCOL",
        operands=(
            ("actor", ("vstd-actor",)),
            ("object", ("vstd-package-object",)),
        ),
        root_role_decisions=(_verifier_decision("owner.py evaluate raises Refuted or Unavailable over retained owner records"),),
    ),
    ownership_spec(
        "vstd-receipt",
        "RECEIPT",
        (
            "src/verifier/domains/contracts/receipt_authenticity.py",
            "src/verifier/domains/contracts/receipt_chain.py",
            "src/verifier/domains/contracts/receipt_prerequisite_closure.py",
            "src/verifier/domains/contracts/receipt_statics.py",
            "src/verifier/domains/contracts/receipt_validation_replay.py",
        ),
        "declared-receipt-authenticity-chain-and-validation-checks",
        "Receipt authenticity, chain and validation replay check signed receipt statements and ordered receipt chains over declared hardware and subject records; bounded search is a budget, not a measurement.",
        "Checks verify retained receipts and bind installed source bytes; they establish no hardware attestation, deployment, or live receipt issuance.",
        "POLICY",
        "PROTOCOL",
        operands=(
            ("hardware", ("vstd-hardware",)),
            ("subject", ("vstd-package-object",)),
        ),
        root_role_decisions=(_verifier_decision("receipt_validation_replay.py recheck_receipt_validation_replay_certificate re-derives retained receipt certificates"),),
    ),
)
CONTRACTS_PREFIX = "src/verifier/domains/contracts/"

# Registry modules are the closed ROUTE_REGISTRY dependencies.  A call or mapping
# lookup resolved through one of them is registry dispatch.
_REGISTRY_MODULES: tuple[str, ...] = tuple(sorted(
    module for module, (klass, _) in EXTERNAL_EVIDENCE_DEPENDENCIES.items() if klass == "ROUTE_REGISTRY"
))

# Batch-local mode of each object's VERIFIER root decision.  The shared root model
# admits only APPLIES or DOES_NOT_APPLY, so an UNKNOWN root would export no
# RootRoleDecision and surface only through the decision table.
ROOT_ROLE_MODES: Mapping[str, Literal["APPLIES", "DOES_NOT_APPLY", "UNKNOWN"]] = {
    "vstd-environment": "APPLIES",
    "vstd-event": "APPLIES",
    "vstd-package-graph": "APPLIES",
    "vstd-hypergraph": "APPLIES",
    "vstd-identity": "APPLIES",
    "vstd-space": "APPLIES",
    "vstd-time": "APPLIES",
    "vstd-role": "APPLIES",
    "vstd-owner": "APPLIES",
    "vstd-receipt": "APPLIES",
}

# APPLIES decisions: the owned-file symbols whose live executable lines carry the
# role test.  Every other accumulating role is decided by the tables below or
# defaults to DOES_NOT_APPLY over the whole of each owned file.
_APPLIES_EVIDENCE: Mapping[tuple[str, str], tuple[tuple[str, str], ...]] = {
    ("vstd-environment", "POLICY"): ((CONTRACTS_PREFIX + "env_checks.py", "_policy"),),
    ("vstd-environment", "VERIFIER"): ((CONTRACTS_PREFIX + "env_checks.py", "recheck_env_checks_certificate"),),
    ("vstd-event", "POLICY"): ((CONTRACTS_PREFIX + "event_closure.py", "_evaluate"),),
    ("vstd-event", "PROTOCOL"): ((CONTRACTS_PREFIX + "event_dispatch.py", "_replay_log"),),
    ("vstd-event", "TRANSACTION"): ((CONTRACTS_PREFIX + "event_dispatch.py", "_replay_log"),),
    ("vstd-event", "VERIFIER"): ((CONTRACTS_PREFIX + "event_dispatch.py", "recheck_event_dispatch_certificate"),),
    ("vstd-package-graph", "POLICY"): ((CONTRACTS_PREFIX + "graph_statics.py", "_policy"),),
    ("vstd-package-graph", "VERIFIER"): ((CONTRACTS_PREFIX + "graph_closure.py", "recheck_graph_closure_certificate"),),
    ("vstd-hypergraph", "ACTUATOR"): ((CONTRACTS_PREFIX + "hyper_unknown_absorption.py", "bound_children"),),
    ("vstd-hypergraph", "POLICY"): ((CONTRACTS_PREFIX + "hyper_closure.py", "_policy"),),
    ("vstd-hypergraph", "VERIFIER"): ((CONTRACTS_PREFIX + "hyper_closure.py", "recheck_hyper_closure_certificate"),),
    ("vstd-identity", "POLICY"): ((CONTRACTS_PREFIX + "identity_lifecycle.py", "_policy"),),
    ("vstd-identity", "PROTOCOL"): ((CONTRACTS_PREFIX + "identity_presentation.py", "_verify_signature"),),
    ("vstd-identity", "VERIFIER"): ((CONTRACTS_PREFIX + "identity_lifecycle.py", "recheck_identity_lifecycle_certificate"),),
    ("vstd-space", "POLICY"): ((CONTRACTS_PREFIX + "space_layout.py", "_policy"),),
    ("vstd-space", "VERIFIER"): ((CONTRACTS_PREFIX + "space_closure.py", "recheck_space_closure_certificate"),),
    ("vstd-time", "POLICY"): ((CONTRACTS_PREFIX + "time_closure.py", "_policy"),),
    ("vstd-time", "VERIFIER"): ((CONTRACTS_PREFIX + "time_order.py", "recheck_time_order_certificate"),),
    ("vstd-role", "POLICY"): ((CONTRACTS_PREFIX + "role_constraints.py", "_policy"),),
    ("vstd-role", "PROTOCOL"): ((CONTRACTS_PREFIX + "role_closure.py", "_evaluate"),),
    ("vstd-role", "VERIFIER"): ((CONTRACTS_PREFIX + "role_closure.py", "recheck_role_closure_certificate"),),
    ("vstd-owner", "ASSET"): (("src/verifier/domains/owner.py", "evaluate"),),
    ("vstd-owner", "POLICY"): ((CONTRACTS_PREFIX + "owner_eligibility.py", "_policy"),),
    ("vstd-owner", "PROTOCOL"): ((CONTRACTS_PREFIX + "owner_replay.py", "_replay"),),
    ("vstd-owner", "VERIFIER"): (("src/verifier/domains/owner.py", "evaluate"),),
    ("vstd-receipt", "POLICY"): ((CONTRACTS_PREFIX + "receipt_authenticity.py", "_policy"),),
    ("vstd-receipt", "PROTOCOL"): ((CONTRACTS_PREFIX + "receipt_authenticity.py", "_evaluate"),),
    ("vstd-receipt", "VERIFIER"): ((CONTRACTS_PREFIX + "receipt_validation_replay.py", "recheck_receipt_validation_replay_certificate"),),
}

# UNKNOWN decisions: a role signal is present at the cited symbols and its semantics
# are not established.  These never enter specializations and block aggregation.
_UNKNOWN_EVIDENCE: Mapping[tuple[str, str], tuple[tuple[str, str], ...]] = {
    ("vstd-environment", "MEASUREMENT"): (("src/verifier/domains/env.py", "evaluate"),),
    ("vstd-identity", "CONTROLLER"): (
        (CONTRACTS_PREFIX + "identity_presentation.py", "_evaluate"),
        (CONTRACTS_PREFIX + "identity_presentation.py", "_exit_probe"),
    ),
    ("vstd-receipt", "MEASUREMENT"): ((CONTRACTS_PREFIX + "receipt_statics.py", "_execution"),),
}
_UNKNOWN_REASONS: Mapping[tuple[str, str], str] = {
    ("vstd-environment", "MEASUREMENT"): "env.py evaluate compares a retained wall_seconds and memory_bytes against ceilings: these are budget bounds, not measurements, and no declared phenomenon, method, units or uncertainty binds them, so MEASUREMENT stays UNKNOWN until a full declaration is bound or an executable full-source refutation runs",
    ("vstd-identity", "CONTROLLER"): "identity_presentation.py _evaluate and _exit_probe carry the holder-signed terminal_controller probe whose controller_id is a witness; no submitted or directed action fed by an observed result is established, so CONTROLLER stays UNKNOWN until feedback, authority, timing, stability or intervention is bound or an executable refutation runs",
    ("vstd-receipt", "MEASUREMENT"): "receipt_statics.py _execution decodes a retained elapsed_ms JSON number into ExecutionMetadata: it observes no latency phenomenon, declares no method, time base, unit or uncertainty, and reads no clock, so MEASUREMENT stays UNKNOWN until a declared latency measurand is bound",
}

# Reasons for the APPLIES cells, each naming the symbol and the fact that carries it.
_APPLIES_REASONS: Mapping[tuple[str, str], str] = {
    ("vstd-environment", "POLICY"): "POLICY APPLIES: env_checks.py _policy admits the declared environment policy through retained_selection before any check replays",
    ("vstd-event", "POLICY"): "POLICY APPLIES: event_closure.py _evaluate hands a policy= keyword to its checker before replaying the retained event closure",
    ("vstd-event", "PROTOCOL"): "PROTOCOL APPLIES: event_dispatch.py _replay_log enforces the event not in topic_of and pair not in pending ordering, dispatch-before-emission and ack-before-dispatch",
    ("vstd-event", "TRANSACTION"): "TRANSACTION APPLIES: event_dispatch.py _replay_log treats an acknowledged dispatch as the commit semantics, not a hash commitment",
    ("vstd-package-graph", "POLICY"): "POLICY APPLIES: graph_statics.py _policy admits the declared package-graph policy before the statics replay",
    ("vstd-hypergraph", "ACTUATOR"): "ACTUATOR APPLIES: hyper_unknown_absorption.py bound_children dispatches a data-chosen selection coordinate through the current_object_routes registry (replay_current_object_certificate), a route-registry dispatch of a data-indexed selector",
    ("vstd-hypergraph", "POLICY"): "POLICY APPLIES: hyper_closure.py _policy admits the declared hypergraph policy before the closure replays",
    ("vstd-identity", "POLICY"): "POLICY APPLIES: identity_lifecycle.py _policy admits the declared identity lifecycle policy",
    ("vstd-identity", "PROTOCOL"): "PROTOCOL APPLIES: identity_presentation.py _verify_signature checks the signed presentation statements, an ordered protocol statement",
    ("vstd-space", "POLICY"): "POLICY APPLIES: space_layout.py _policy admits the declared layout policy before the layout replays",
    ("vstd-time", "POLICY"): "POLICY APPLIES: time_closure.py _policy admits the declared time policy before the closure replays",
    ("vstd-role", "POLICY"): "POLICY APPLIES: role_constraints.py _policy admits the role-constraints policy through retained_selection.policy (corrected from the earlier _evaluate matrix span)",
    ("vstd-role", "PROTOCOL"): "PROTOCOL APPLIES: role_closure.py _evaluate replays ordered take and leave handovers keyed by taking and leaving",
    ("vstd-owner", "ASSET"): "ASSET APPLIES: owner.py evaluate records holdings under the registry ASSET contract; the three ASSET obligations stay open blockers",
    ("vstd-owner", "POLICY"): "POLICY APPLIES: owner_eligibility.py _policy admits the declared owner eligibility policy",
    ("vstd-owner", "PROTOCOL"): "PROTOCOL APPLIES: owner_replay.py _replay orders owner events by their from-owner key",
    ("vstd-receipt", "POLICY"): "POLICY APPLIES: receipt_authenticity.py _policy admits the declared receipt policy",
    ("vstd-receipt", "PROTOCOL"): "PROTOCOL APPLIES: receipt_authenticity.py _evaluate checks signed receipt statements",
}

# Object facts for the DOES_NOT_APPLY reasons: the reads and checks each owned set
# actually performs, named by file so the absence claim is tied to real source.
_OBJECT_FACTS: Mapping[str, str] = {
    "vstd-environment": "env_checks.py, env_checks_projection.py, env_configuration_surface.py, env_executable.py and env_pin_closure.py replay retained process observations and installed mechanism bytes through read_bytes digest pins, and env.py collect_configuration reads host platform identity only",
    "vstd-event": "event_closure.py, event_dispatch.py and event_prerequisites.py replay supplied event logs; their only file reads are read_bytes digest pins of retained inputs and installed source",
    "vstd-package-graph": "graph_closure.py, graph_lineage.py, graph_order.py and graph_statics.py check declared package membership and topological order from retained declarations and installed source bytes",
    "vstd-hypergraph": "hyper_closure.py and hyper_composed_ceiling.py compose retained tier results, the composed ceiling being a min over tiers, while hyper_unknown_absorption.py is the one owned file that dispatches a data-chosen objective",
    "vstd-identity": "identity.py evaluate, identity_lifecycle.py, identity_lifecycle_replay.py, identity_occupancy.py, identity_presentation.py and identity_scope.py verify retained signed statements, bounded occupancy and declared lifecycle policy, and signature checks are protocol checking, not sensing",
    "vstd-space": "space_closure.py, space_layout.py and space_migration.py bind retained layouts and compare declared logical bytes against budgets",
    "vstd-time": "time_closure.py, time_order.py and time_strict.py compare declared sample instants for order and span, and no live clock is read",
    "vstd-role": "role.py evaluate, role_closure.py, role_constraints.py and role_lifecycle.py replay supplied take, leave and handover events under declared policy",
    "vstd-owner": "owner.py evaluate, owner_eligibility.py, owner_forks.py and owner_replay.py compare retained owner records and ordered replays, and holdings are recorded only under the ASSET contract",
    "vstd-receipt": "receipt_authenticity.py, receipt_chain.py, receipt_prerequisite_closure.py, receipt_statics.py and receipt_validation_replay.py verify retained signed receipts, ordered chains and bounded search",
}

# Next action for each DOES_NOT_APPLY role: the concrete source change that would
# overturn the cell.
_ROLE_NEXT: Mapping[str, str] = {
    "ACTUATOR": "re-derive this cell if a route-registry dispatch of a data-chosen coordinate reaches these files",
    "ASSET": "a recorded-holding path would need the ASSET contract and its three open obligations bound",
    "CONTROLLER": "a submitted action fed by an observed result would need a CONTROLLER decision",
    "FINBOT": "a trading or broker route would need a FINBOT decision",
    "LEDGER": "a balance-mutating or debit or credit path would need a LEDGER decision",
    "MARKET": "a market or price route would need a MARKET decision",
    "MEASUREMENT": "a declared phenomenon with units, method and uncertainty or missingness would need a MEASUREMENT decision",
    "POLICY": "a _policy admission in these files would overturn this absence",
    "PROTOCOL": "an ordered handover, dispatch-before-emission ordering or signed statement would need a PROTOCOL decision",
    "ROBOT": "a robot or motor path would need a ROBOT decision",
    "SENSOR": "an ADC or sensor acquisition beside calibration, envelope or fault semantics would need a SENSOR decision",
    "TRANSACTION": "a commit, acknowledgement or idempotency path would need a TRANSACTION decision",
}


def _whole_file_evidence(paths: tuple[str, ...]) -> tuple[SourceEvidence, ...]:
    """Cite every owned file whole, so an absence claim covers the full bytes."""
    return tuple(SourceEvidence(path, _MODULE_SYMBOL, 1, _LINE_COUNTS[path]) for path in paths)


def _symbol_evidence(refs: tuple[tuple[str, str], ...]) -> tuple[SourceEvidence, ...]:
    return tuple(SourceEvidence(path, symbol, *_SPANS[(path, symbol)]) for path, symbol in refs)


def _dna_reason(spec: SemanticOwnershipSpec, role: str) -> str:
    return (f"{role} DOES_NOT_APPLY: the AST scan of the {len(spec.owned_paths)} owned files, "
            f"including dead lines, found no instance of {ROLE_TESTS[role]}; {_OBJECT_FACTS[spec.object_id]}; "
            f"{_ROLE_NEXT[role]}")


def _build_decisions() -> tuple[SourceRoleDecision, ...]:
    rows = []
    for spec in DOMAIN_CONTEXT_OWNERSHIP_SPECS:
        for role in DECIDED_ROLES:
            key = (spec.object_id, role)
            if role == ROOT_ROLE:
                rows.append(SourceRoleDecision(
                    spec.object_id, role, ROOT_ROLE_MODES[spec.object_id],
                    _symbol_evidence(_APPLIES_EVIDENCE[key]),
                    spec.root_role_decisions[0].reason,
                ))
            elif key in _UNKNOWN_EVIDENCE:
                rows.append(SourceRoleDecision(
                    spec.object_id, role, "UNKNOWN",
                    _symbol_evidence(_UNKNOWN_EVIDENCE[key]),
                    _UNKNOWN_REASONS[key],
                ))
            elif key in _APPLIES_EVIDENCE:
                rows.append(SourceRoleDecision(
                    spec.object_id, role, "APPLIES",
                    _symbol_evidence(_APPLIES_EVIDENCE[key]),
                    _APPLIES_REASONS[key],
                ))
            else:
                rows.append(SourceRoleDecision(
                    spec.object_id, role, "DOES_NOT_APPLY",
                    _whole_file_evidence(spec.owned_paths),
                    _dna_reason(spec, role),
                ))
    return tuple(rows)


DOMAIN_CONTEXT_ROLE_DECISIONS: tuple[SourceRoleDecision, ...] = _build_decisions()




def open_blockers() -> tuple[str, ...]:
    """Return the named blockers that this batch reports rather than exempts."""
    return OPEN_LAYOUT_BLOCKERS + ASSET_OBLIGATION_BLOCKERS


def unknown_decisions(decisions: tuple[SourceRoleDecision, ...] = DOMAIN_CONTEXT_ROLE_DECISIONS) -> tuple[SourceRoleDecision, ...]:
    """Return every UNKNOWN cell, which stays visible rather than defaulting."""
    return tuple(decision for decision in decisions if decision.status == UNKNOWN_STATUS)


def decision_counts(decisions: tuple[SourceRoleDecision, ...] = DOMAIN_CONTEXT_ROLE_DECISIONS) -> dict[str, int]:
    """Count cells by status; UNKNOWN is a separate count, never DOES_NOT_APPLY."""
    return {status: sum(1 for decision in decisions if decision.status == status) for status in STATUSES}


def aggregation_blockers(decisions: tuple[SourceRoleDecision, ...] = DOMAIN_CONTEXT_ROLE_DECISIONS) -> tuple[str, ...]:
    """Return every reason aggregation or readiness is blocked, one line each."""
    blockers = [f"{decision.object_id} {decision.role} UNKNOWN: {decision.reason}"
                for decision in unknown_decisions(decisions)]
    blockers.extend(f"open blocker: {text}" for text in open_blockers())
    return tuple(blockers)


def require_aggregation_ready(decisions: tuple[SourceRoleDecision, ...] = DOMAIN_CONTEXT_ROLE_DECISIONS) -> None:
    """Refuse aggregation while any UNKNOWN cell or open blocker remains."""
    blockers = aggregation_blockers(decisions)
    if blockers:
        raise ValueError("DOMAIN_CONTEXT_AGGREGATION_BLOCKED: " + "; ".join(blockers))


def _fail(code: str, detail: str) -> NoReturn:
    raise ValueError(f"{code}: {detail}")


def _portable(path: str) -> bool:
    pure = PurePosixPath(path)
    return (
        path.startswith(_PATH_PREFIX)
        and not pure.is_absolute()
        and ".." not in pure.parts
        and "\\" not in path
        and path == pure.as_posix()
    )


def _validate(
    specs: tuple[SemanticOwnershipSpec, ...],
    decisions: tuple[SourceRoleDecision, ...],
    census: tuple[SourceCensusRow, ...],
    digests: Mapping[str, str],
) -> None:
    """Pure, dependency-free validation of rows, census and decisions."""
    paths = tuple(row.path for row in census)
    if paths != tuple(sorted(paths)) or len(set(paths)) != len(paths):
        _fail("DOMAIN_CONTEXT_CENSUS_ORDER", "census must be sorted and unique")
    if len(paths) != 41:
        _fail("DOMAIN_CONTEXT_CENSUS_SIZE", f"expected 41 census paths, found {len(paths)}")
    for row in census:
        if not _portable(row.path) or row.lines <= 0 or not _DIGEST.fullmatch(row.sha256):
            _fail("DOMAIN_CONTEXT_CENSUS_ROW", row.path)
        if digests.get(row.path) != row.sha256:
            _fail("DOMAIN_CONTEXT_DIGEST_COVERAGE", row.path)
    if set(digests) != set(paths):
        _fail("DOMAIN_CONTEXT_DIGEST_COVERAGE", "digest map keys differ from census")

    kinds = tuple(spec.primary_kind for spec in specs)
    if tuple(sorted(kinds)) != tuple(sorted(PRIMARY_KINDS)) or len(set(kinds)) != len(kinds):
        _fail("DOMAIN_CONTEXT_KIND_COVERAGE", f"primary kinds {kinds}")
    owned_all: list[str] = []
    seen_ids: set[str] = set()
    for spec in specs:
        if not _OBJECT_ID.fullmatch(spec.object_id) or spec.object_id in seen_ids:
            _fail("DOMAIN_CONTEXT_OBJECT_ID", spec.object_id)
        seen_ids.add(spec.object_id)
        if spec.primary_kind == "OBJECT":
            _fail("DOMAIN_CONTEXT_OBJECT_FALLBACK", spec.object_id)
        if not spec.owned_paths or any(not _portable(path) for path in spec.owned_paths):
            _fail("DOMAIN_CONTEXT_PATH", spec.object_id)
        owned_all.extend(spec.owned_paths)
        decided = {d.role: d for d in decisions if d.object_id == spec.object_id}
        unknown = {role for role, d in decided.items() if d.status == UNKNOWN_STATUS}
        if set(spec.specializations) & unknown:
            _fail("DOMAIN_CONTEXT_UNKNOWN_SPECIALIZATION",
                  f"{spec.object_id} specializes unresolved roles {sorted(set(spec.specializations) & unknown)}")
        applies = {role for role, d in decided.items() if d.status == "APPLIES" and role != ROOT_ROLE}
        if tuple(sorted(applies)) != tuple(sorted(spec.specializations)):
            _fail("DOMAIN_CONTEXT_SPECIALIZATION", f"{spec.object_id} accumulated roles differ from decisions")
        if spec.representation_role == "" or spec.necessity_reason == "" or spec.consequence_boundary == "":
            _fail("DOMAIN_CONTEXT_TEXT", spec.object_id)
        roots = {r.kind: r for r in spec.root_role_decisions}
        verifier = decided.get(ROOT_ROLE)
        if verifier is None or verifier.status != ROOT_ROLE_MODES.get(spec.object_id):
            _fail("DOMAIN_CONTEXT_ROOT_ROLE", f"{spec.object_id} VERIFIER status differs from the batch root mode")
        if verifier.status == UNKNOWN_STATUS:
            if roots:
                _fail("DOMAIN_CONTEXT_ROOT_ROLE", f"{spec.object_id} exports an UNKNOWN root the shared model cannot represent")
        elif (set(roots) != {ROOT_ROLE} or roots[ROOT_ROLE].status != verifier.status
              or roots[ROOT_ROLE].reason != verifier.reason):
            _fail("DOMAIN_CONTEXT_ROOT_ROLE", f"{spec.object_id} VERIFIER row differs from table")
        _validate_operands(spec)
    if len(owned_all) != len(set(owned_all)) or set(owned_all) != set(paths):
        missing = sorted(set(paths) - set(owned_all))
        extra = sorted(set(owned_all) - set(paths))
        _fail("DOMAIN_CONTEXT_COVERAGE", f"missing={missing} extra={extra} or duplicated")

    for spec in specs:
        decided = {d.role: d for d in decisions if d.object_id == spec.object_id}
        if tuple(sorted(decided)) != tuple(sorted(DECIDED_ROLES)):
            _fail("DOMAIN_CONTEXT_DECISION_COVERAGE", f"{spec.object_id} roles {sorted(decided)}")
    for decision in decisions:
        if decision.status not in STATUSES:
            _fail("DOMAIN_CONTEXT_STATUS", f"{decision.object_id} {decision.role} {decision.status}")
        if not decision.reason:
            _fail("DOMAIN_CONTEXT_REASON", f"{decision.object_id} {decision.role}")
        spec = next((s for s in specs if s.object_id == decision.object_id), None)
        if spec is None:
            _fail("DOMAIN_CONTEXT_DECISION_OBJECT", decision.object_id)
        if not decision.evidence:
            _fail("DOMAIN_CONTEXT_EVIDENCE", f"{decision.object_id} {decision.role} has no evidence")
        for ev in decision.evidence:
            if ev.path not in spec.owned_paths:
                _fail("DOMAIN_CONTEXT_EVIDENCE_OWNER", f"{decision.object_id} {ev.path}")
            if not _SYMBOL.fullmatch(ev.symbol):
                _fail("DOMAIN_CONTEXT_EVIDENCE_SYMBOL", ev.symbol)
            if not (1 <= ev.start_line <= ev.end_line <= _LINE_COUNTS[ev.path]):
                _fail("DOMAIN_CONTEXT_EVIDENCE_SPAN", f"{ev.path}:{ev.symbol}")
        if not any(Path(ev.path).name in decision.reason for ev in decision.evidence):
            _fail("DOMAIN_CONTEXT_REASON", f"{decision.object_id} {decision.role} reason cites no evidence file")
        if decision.status == "DOES_NOT_APPLY":
            whole = {(ev.path, ev.symbol) for ev in decision.evidence}
            if whole != {(path, _MODULE_SYMBOL) for path in spec.owned_paths}:
                _fail("DOMAIN_CONTEXT_DNA_EVIDENCE", f"{decision.object_id} {decision.role} must cite every owned file whole")
            for ev in decision.evidence:
                if (ev.start_line, ev.end_line) != (1, _LINE_COUNTS[ev.path]):
                    _fail("DOMAIN_CONTEXT_DNA_EVIDENCE", f"{ev.path} not whole-file")
        elif any(ev.symbol == _MODULE_SYMBOL for ev in decision.evidence):
            code = "DOMAIN_CONTEXT_UNKNOWN_EVIDENCE" if decision.status == UNKNOWN_STATUS else "DOMAIN_CONTEXT_APPLIES_EVIDENCE"
            _fail(code, f"{decision.object_id} {decision.role} cites module")


def _validate_operands(spec: SemanticOwnershipSpec) -> None:
    names = {name for name, _ in spec.operands}
    for name, targets in spec.operands:
        if not _OPERAND_ROLE.fullmatch(name) or not targets:
            _fail("DOMAIN_CONTEXT_OPERAND", f"{spec.object_id} {name}")
    if spec.primary_kind in ZERO_OPERAND_KINDS:
        if spec.operands:
            _fail("DOMAIN_CONTEXT_OPERAND", f"{spec.object_id} must have no operands")
    elif spec.primary_kind in REQUIRED_OPERAND_ROLES:
        if names != REQUIRED_OPERAND_ROLES[spec.primary_kind]:
            _fail("DOMAIN_CONTEXT_OPERAND", f"{spec.object_id} operands {sorted(names)}")
    elif spec.primary_kind == "GRAPH" and spec.operands:
        _fail("DOMAIN_CONTEXT_OPERAND", "GRAPH operands are an open blocker")
    elif spec.primary_kind == "HYPER" and not spec.operands:
        _fail("DOMAIN_CONTEXT_OPERAND", "HYPER requires operands")


def validate_domain_context() -> None:
    """Validate the module's own rows, census, digests and decision table."""
    _validate(
        DOMAIN_CONTEXT_OWNERSHIP_SPECS,
        DOMAIN_CONTEXT_ROLE_DECISIONS,
        DOMAIN_CONTEXT_SOURCE_CENSUS,
        DOMAIN_CONTEXT_SOURCE_DIGESTS,
    )


def _symbol_node(tree: ast.Module, symbol: str) -> ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | None:
    """Resolve a top-level function or class by its exact name."""
    for child in tree.body:
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and child.name == symbol:
            return child
    return None
def evidence_failures(root: Path | str, decisions: tuple[SourceRoleDecision, ...] = DOMAIN_CONTEXT_ROLE_DECISIONS) -> tuple[str, ...]:
    """Check every cited span of the audited root against its AST role test.

    APPLIES needs a live test hit in the span and the role's requirement.  DOES_NOT_APPLY
    needs no test hit anywhere in the cited file, dead lines included, so an absence
    claim fails closed when the mechanism is present in the bytes.  UNKNOWN needs a
    hit and must not already satisfy the requirement for APPLIES.
    """
    base = Path(root)
    failures: list[str] = []
    cache: dict[str, tuple[_Scan, str, dict[int, str]]] = {}

    def load(path: str) -> tuple[_Scan, str, dict[int, str]]:
        if path not in cache:
            text = (base / path).read_text(encoding="utf-8")
            cache[path] = (_scan(text), text, _code_lines(text))
        return cache[path]

    for decision in decisions:
        signals = 0
        for ev in decision.evidence:
            if not (base / ev.path).is_file():
                failures.append(f"{ev.path}: missing")
                continue
            scan, text, code = load(ev.path)
            # A whole-file citation is stale when the file has changed; the test window is
            # then the current file, so appended mechanism is never hidden by a stale span.
            window = (1, len(text.splitlines()))
            if ev.symbol == _MODULE_SYMBOL:
                if (ev.start_line, ev.end_line) != window:
                    failures.append(f"{ev.path}: module span is not whole-file")
            else:
                node = _symbol_node(scan.tree, ev.symbol)
                if node is None:
                    failures.append(f"{ev.path}:{ev.symbol}: symbol missing")
                    continue
                start = min([node.lineno, *[d.lineno for d in node.decorator_list]])
                end = node.end_lineno or node.lineno
                if not (start <= ev.start_line <= ev.end_line <= end):
                    failures.append(f"{ev.path}:{ev.symbol}: span outside symbol {start}-{end}")
                if not any(ev.start_line <= number <= ev.end_line for number in code):
                    failures.append(f"{ev.path}:{ev.symbol}: span holds only docstring or comment lines")
                window = (ev.start_line, ev.end_line)
            hits = [number for number in _hits(decision.role, scan) if window[0] <= number <= window[1]]
            live = [number for number in hits if number not in scan.dead]
            tokens = _span_tokens(scan, *window)
            signals += len(hits)
            if decision.status == "APPLIES":
                if not live:
                    failures.append(f"{decision.object_id} {decision.role}: {ev.path}:{ev.symbol} has no live {decision.role} test")
                gap = _requirement_gap(decision.role, tokens)
                if gap:
                    failures.append(f"{decision.object_id} {decision.role}: {ev.path}:{ev.symbol} lacks {gap}")
            if decision.status == "DOES_NOT_APPLY" and hits:
                failures.append(f"{decision.object_id} {decision.role}: {ev.path} line {hits[0]} matches the {decision.role} test")
            if decision.status == UNKNOWN_STATUS and live and _requirement_gap(decision.role, tokens) is None:
                failures.append(f"{decision.object_id} {decision.role}: {ev.path}:{ev.symbol} satisfies the APPLIES requirement; promote the cell")
        if decision.status == UNKNOWN_STATUS and not signals:
            failures.append(f"{decision.object_id} {decision.role}: UNKNOWN cites no {decision.role} signal line")
    return tuple(failures)




def source_drift_failures(root: Path | str, census: tuple[SourceCensusRow, ...] = DOMAIN_CONTEXT_SOURCE_CENSUS) -> tuple[str, ...]:
    """Compare each census file's raw-byte digest and line count with disk."""
    base = Path(root)
    failures: list[str] = []
    for row in census:
        path = base / row.path
        if not path.is_file():
            failures.append(f"{row.path}: missing")
            continue
        data = path.read_bytes()
        if "sha256:" + hashlib.sha256(data).hexdigest() != row.sha256:
            failures.append(f"{row.path}: digest drift")
        if len(data.splitlines()) != row.lines:
            failures.append(f"{row.path}: line count drift")
    return tuple(failures)
__all__ = (
    "ACCUMULATING_ROLES",
    "DECIDED_ROLES",
    "DOMAIN_CONTEXT_OWNERSHIP_SPECS",
    "DOMAIN_CONTEXT_PATH_CENSUS",
    "DOMAIN_CONTEXT_ROLE_DECISIONS",
    "DOMAIN_CONTEXT_SOURCE_CENSUS",
    "DOMAIN_CONTEXT_SOURCE_DIGESTS",
    "EXTERNAL_EVIDENCE_DEPENDENCIES",
    "OPEN_LAYOUT_BLOCKERS",
    "PRIMARY_KINDS",
    "ROLE_TESTS",
    "ROOT_ROLE",
    "ROOT_ROLE_MODES",
    "STATUSES",
    "SourceCensusRow",
    "SourceEvidence",
    "SourceRoleDecision",
    "aggregation_blockers",
    "decision_counts",
    "evidence_failures",
    "gate_hits",
    "open_blockers",
    "require_aggregation_ready",
    "source_digest",
    "source_drift_failures",
    "unknown_decisions",
    "validate_domain_context",
)
