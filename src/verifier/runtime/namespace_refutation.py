"""Neutral, fail-closed closure runs and witnesses for DOES_NOT_APPLY namespace decisions.

A DOES_NOT_APPLY claim is judged by a fresh run, inside the current assessment, of
the closure that this installed module registers for its kind.  Without a stored
witness, ``judge_census_closure`` runs it over the object's exact current owned
census, which the caller supplies as paths and digests.  With a stored witness,
``establish_dne_witness`` first requires the witness's object, kind, basis, review
module, review mechanism, review row and anchored source bytes to match explicit
expected inputs, then runs the closure over its anchored census.  Binding is
necessary and never sufficient.  Either run's receipt binds the same identity and
census; a clean run is bounded evidence only (see below).

The module reads no files, environment or working directory.  Source bytes reach
it only through a caller-supplied ``read`` callable, and it imports only the
standard library and no other Verifier module, so the classification, admission
and package layers can depend on it without cycles.  No subject code is ever
executed: a registered closure is a fixed scan of anchored text.

Trust boundary: a receipt is produced only by a fresh run inside
``establish_dne_witness`` or ``judge_census_closure``.  A manifest can never supply
one, because the witness schema has no receipt field and extra keys fail.  Digests
make a receipt tamper-evident, not authentic against code that already runs
in-process.

Each of the thirty-eight installed kinds owns its own registered boundary
closure.  Original kinds and consequential extensions use the same fresh,
source-bound admission rule; neither an old wire label nor generic ``OBJECT``
may make non-applicability self-authenticating.  A closure run performs three bounded steps over the
exact anchored census: a boundary-identifier scan (FAIL on any whole-word reference),
then shared gates that return UNKNOWN for unsupported languages, dynamic lookup or
reflection, and process, network or external-store effects.  Only a scan with no
reference and no gate hit yields a clean PASS observation.  Each receipt binds the
closure definition digest, which pins identifiers, matching rules, gates and claim,
and the limits digest in effect.  An unregistered future kind still remains UNKNOWN,
so namespace extension cannot silently inherit a checker written for a different
semantic boundary.

A clean PASS is bounded evidence only.  Absence of listed spellings in a finite text
census cannot show that a kind does not apply, so it is judged UNKNOWN with code
BOUNDED_ABSENCE_OBSERVED_NOT_NON_APPLICABILITY and keeps its fresh receipt.  No
installed closure returns ESTABLISHED, so no obligation is removed by a closure.
ESTABLISHED is reserved for a stronger mechanism that is not installed here.

AUDITED_SOURCE documents a prose review and is never ESTABLISHED.

Status: ESTABLISHED | AUDITED_NOT_ESTABLISHED | UNKNOWN | FAIL.  UNKNOWN covers
absent, stale, unregistered, unpinned, unreadable, timed-out or bounded-absence
inputs; FAIL covers contradiction (including a registered boundary reference in a
witness's census, after identifier variants are matched), forgery and malformed
shape.  A census run reports a boundary reference as UNKNOWN, because no reviewer
bound a claim for it to contradict.  This module never
admits a DOES_NOT_APPLY by itself.  The classification layer admits one as
DOCUMENTED, never ESTABLISHED, only when this module's bounded-absence observation,
a clean owned closed-effect audit and the decision's reason with current owned
evidence all hold.  DOCUMENTED removes no obligation; only ESTABLISHED could refute a
hint.
"""
from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import re
import time
import tokenize
import unicodedata
from typing import Any, Callable


SCHEMA = "verifier-dne-refutation-witness-1"
CLOSURE_SCHEMA = "verifier-dne-closure-receipt-2"
CLOSURE_ALGORITHM = "KIND_BOUNDARY_ABSENCE_V4"
_PYTHON_GATE_LEXING = "TOKENIZE_MASK_COMMENT_NON_FORMAT_STRING_AND_RE_COMPILE_V2"
DECISION_STATUS = "DOES_NOT_APPLY"
BASIS_EXECUTABLE_CLOSURE = "EXECUTABLE_CLOSURE"
BASIS_AUDITED_SOURCE = "AUDITED_SOURCE"
BASES = frozenset({BASIS_EXECUTABLE_CLOSURE, BASIS_AUDITED_SOURCE})
MANIFEST_PATH = "objects.vstd"

MAX_SOURCE_ANCHORS = 16
MAX_CALLEE_ANCHORS = 128
MAX_PATH_BYTES = 200
MAX_WITNESS_BYTES = 65536
MAX_INVENTORY_ENTRIES = 50000
MAX_ANCHOR_BYTES = 1024 * 1024
MAX_CLOSURE_BYTES = 4 * 1024 * 1024
MAX_CLOSURE_SECONDS = 5.0
_MAX_IDENTIFIER = 200
_MAX_KIND = 64
_MAX_DETAIL = 256

ESTABLISHED = "ESTABLISHED"
AUDITED_NOT_ESTABLISHED = "AUDITED_NOT_ESTABLISHED"
UNKNOWN = "UNKNOWN"
FAIL = "FAIL"
STATUSES = frozenset({ESTABLISHED, AUDITED_NOT_ESTABLISHED, UNKNOWN, FAIL})

CLOSURE_PASS = "PASS"
CLOSURE_FAIL = "FAIL"
CLOSURE_UNKNOWN = "UNKNOWN"
CLOSURE_STATUSES = frozenset({CLOSURE_PASS, CLOSURE_FAIL, CLOSURE_UNKNOWN})
PASS_CODE = "NO_BOUNDARY_IDENTIFIER_REFERENCED"
REFERENCE_CODE = "BOUNDARY_IDENTIFIER_REFERENCED"
# The judged form of a clean PASS: bounded evidence, never an establishment.
BOUNDED_ABSENCE_CODE = "BOUNDED_ABSENCE_OBSERVED_NOT_NON_APPLICABILITY"

_WITNESS_KEYS = frozenset({
    "schema", "object_id", "kind", "decision_status", "basis", "review_module",
    "review_mechanism_digest", "review_row_digest", "source_anchors", "callee_anchors",
    "witness_digest",
})
RECEIPT_KEYS = frozenset({
    "schema", "object_id", "kind", "closure_id", "closure_digest", "decision_row_digest",
    "mechanism_digest", "limits_digest", "anchors", "census_digest", "status", "code",
    "detail", "receipt_digest",
})
_ANCHOR_KEYS = frozenset({"path", "sha256"})
_INVENTORY_KEYS = frozenset({"owner", "sha256", "available"})
_RESERVED_NAMES = frozenset({"con", "prn", "aux", "nul"}
                            | {f"com{index}" for index in range(1, 10)}
                            | {f"lpt{index}" for index in range(1, 10)})
# A segment may start with one dot, so census paths such as .github/workflows/ci.yml bind;
# ".", "..", a doubled leading dot, a trailing dot and every other malformed segment fail closed.
_SEGMENT = r"\.?[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?"
_PATH_RE = re.compile(_SEGMENT + r"(?:/" + _SEGMENT + r")*")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_MODULE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
_OBJECT_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:/@-]*")
_KIND_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]*")
_TOKEN_RE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")


@dataclasses.dataclass(frozen=True)
class ExpectedReview:
    """Caller-established identity that a witness must match exactly."""

    object_id: str
    kind: str
    basis: str
    review_module: str
    review_mechanism_digest: str
    review_row_digest: str


@dataclasses.dataclass(frozen=True)
class Closure:
    """One installed refutation closure: a fixed boundary-absence scan for one kind.

    The identifiers name the write or effect boundary of ``kind``.  Absence of
    every one of them, together with the shared gates below, from the exact owned
    census and its callee anchors supports only the ``claim`` text.  This is a
    bounded text check, not a semantic proof: a mention in a comment or string
    still counts against the refutation, which keeps the closure conservative.
    """

    closure_id: str
    kind: str
    identifiers: frozenset[str]
    claim: str


def _boundary(kind: str, identifiers: tuple[str, ...], claim: str) -> Closure:
    return Closure(closure_id="verifier.closure." + kind.lower() + "-boundary-absence-2",
                   kind=kind, identifiers=frozenset(identifiers), claim=claim)


# Closed, installed registry, one independent closure per installed kind.
# Subjects cannot name, add or replace a closure.  A future kind without an entry
# has no closure, so its DOES_NOT_APPLY cannot establish by analogy.
_CLOSURES: dict[str, Closure] = {closure.kind: closure for closure in (
    _boundary("HUMAN", ("request_human_input", "collect_human_response", "identify_human",
                         "authorize_human"),
              "The subject does not identify, solicit, authorize or record a human participant through a human boundary."),
    _boundary("ACTOR", ("act_as_actor", "authorize_actor", "dispatch_actor_action",
                         "record_actor_action"),
              "The subject does not authorize, dispatch or record an actor action through an actor boundary."),
    _boundary("COLLECTIVE", ("add_collective_member", "remove_collective_member",
                              "decide_collective", "vote_collective"),
              "The subject does not constitute membership or make a collective decision through a collective boundary."),
    _boundary("ROLE", ("assign_role", "revoke_role", "resolve_role", "authorize_role"),
              "The subject does not assign, revoke, resolve or authorize a role."),
    _boundary("IDENTITY", ("issue_identity", "resolve_identity", "verify_identity", "bind_identity"),
              "The subject does not issue, resolve, verify or bind an identity."),
    _boundary("OWNER", ("assign_owner", "transfer_ownership", "resolve_owner", "enforce_owner"),
              "The subject does not assign, transfer, resolve or enforce ownership authority."),
    _boundary("HARDWARE", ("read_hardware", "write_hardware", "enumerate_hardware", "control_hardware"),
              "The subject does not enumerate, read, write or control a hardware boundary."),
    _boundary("RECEIPT", ("issue_receipt", "verify_receipt", "record_receipt", "sign_receipt"),
              "The subject does not issue, verify, record or sign a receipt."),
    _boundary("OBJECT", ("create_object", "load_object", "store_object", "resolve_object"),
              "The subject does not create, load, store or resolve a generic object representation."),
    _boundary("GRAPH", ("add_graph_edge", "remove_graph_edge", "traverse_graph", "update_graph"),
              "The subject does not add, remove, traverse or update a graph relation."),
    _boundary("SPACE", ("transform_space", "map_coordinates", "convert_reference_frame",
                         "resolve_position"),
              "The subject does not transform a space, map coordinates, convert a reference frame or resolve a position."),
    _boundary("TIME", ("read_clock", "schedule_time", "advance_time", "timestamp_event"),
              "The subject does not read, schedule, advance or assign time through a time boundary."),
    _boundary("EVENT", ("emit_event", "publish_event", "consume_event", "dispatch_event"),
              "The subject does not emit, publish, consume or dispatch an event."),
    _boundary("ENV", ("read_environment", "write_environment", "load_environment",
                       "configure_environment"),
              "The subject does not read, write, load or configure an execution environment."),
    _boundary("DATA", ("read_data", "write_data", "transform_data", "serialize_data"),
              "The subject does not read, write, transform or serialize a data representation."),
    _boundary("VERIFIER", ("verify_claim", "emit_verdict", "check_obligation", "evaluate_evidence"),
              "The subject does not check an obligation or evidence and emit a verification verdict."),
    _boundary("BENCH", ("run_benchmark", "record_benchmark", "score_benchmark", "compare_benchmark"),
              "The subject does not run, record, score or compare a benchmark."),
    _boundary("ARCH", ("load_architecture", "build_architecture", "execute_architecture",
                        "select_architecture"),
              "The subject does not load, build, execute or select a computational architecture."),
    _boundary("TRAIN", ("train_model", "fit_model", "update_weights", "optimize_parameters"),
              "The subject does not train or fit a model or update learned parameters."),
    _boundary("HYPER", ("compose_hyperstructure", "map_hyperedge", "traverse_hypergraph",
                         "bind_hyperrelation"),
              "The subject does not compose, map, traverse or bind a higher-order relation structure."),
    _boundary("MODEL", ("load_model", "infer_model", "predict_model", "update_model"),
              "The subject does not load, infer, predict with or update a model."),
    _boundary("HARNESS", ("launch_subject", "stop_subject", "capture_subject_output",
                           "enforce_subject_limit"),
              "The subject does not launch, stop, observe or bound another subject through a harness."),
    _boundary("AGENT", ("decide_action", "plan_action", "execute_action", "choose_tool"),
              "The subject does not plan, decide, execute an agent action or choose a tool."),
    _boundary("SIM", ("step_simulation", "reset_simulation", "advance_simulation",
                       "update_simulation"),
              "The subject does not step, reset, advance or update a simulation state."),
    _boundary("BOT", ("step_bot", "decide_bot_action", "act_in_simulation", "update_bot"),
              "The subject does not decide or act as a simulation-situated bot."),
    _boundary("TOKEN", ("issue_token", "revoke_token", "validate_token", "transfer_token"),
              "The subject does not issue, revoke, validate or transfer a token."),
    _boundary("LEDGER", ("append_ledger_entry", "post_ledger_entry", "record_ledger_entry",
                         "write_ledger_entry"),
              "The subject does not write an authoritative ledger entry through a registered write boundary."),
    _boundary("TRANSACTION", ("begin_transaction", "commit_transaction", "rollback_transaction",
                              "apply_transaction", "submit_transaction", "replay_transaction"),
              "The subject does not begin, commit, roll back, apply, submit or replay a coordinated transaction."),
    _boundary("ASSET", ("issue_asset", "redeem_asset", "mint_asset", "burn_asset", "transfer_asset",
                        "encumber_asset"),
              "The subject does not issue, redeem, mint, burn, transfer or encumber a recorded asset claim."),
    _boundary("MARKET", ("submit_order", "place_order", "cancel_order", "match_orders", "execute_trade",
                         "settle_trade"),
              "The subject does not admit, cancel, match, execute or settle market orders or trades."),
    _boundary("MEASUREMENT", ("record_measurement", "write_measurement", "emit_measurement",
                              "publish_measurement", "record_observation"),
              "The subject does not record or publish a measurement or observation value."),
    _boundary("SENSOR", ("read_sensor", "sample_sensor", "poll_sensor", "acquire_sensor_sample"),
              "The subject does not read, sample or poll a sensor through an acquisition boundary."),
    _boundary("CONTROLLER", ("apply_control", "set_setpoint", "write_setpoint", "write_control_output",
                             "issue_control_command"),
              "The subject does not issue a feedback control command or setpoint."),
    _boundary("ACTUATOR", ("drive_actuator", "command_actuator", "set_actuator", "energize_actuator",
                           "actuate"),
              "The subject does not command or drive an actuator."),
    _boundary("PROTOCOL", ("send_message", "broadcast_message", "deliver_message", "transmit_frame",
                           "start_handshake"),
              "The subject does not send, broadcast, deliver or start a protocol message exchange."),
    _boundary("POLICY", ("enforce_policy", "apply_policy", "update_policy", "grant_exception",
                         "revoke_exception", "decide_policy"),
              "The subject does not enforce, apply, update or except a policy decision."),
    _boundary("ROBOT", ("move_robot", "command_robot", "send_motion", "drive_motor", "actuate_robot",
                        "energize_robot"),
              "The subject does not command physical robot motion or actuation."),
    _boundary("FINBOT", ("place_trade", "execute_trade", "transfer_funds", "settle_payment",
                         "approve_payment", "submit_order"),
              "The subject does not place, execute, settle or approve a financial transfer or trade."),
)}

# Shared gates.  A hit is UNKNOWN, never PASS: dynamic lookup, evaluation and
# reflection can reach a boundary through names this scan cannot see, and process,
# network or external-store effects leave the owned text.  Data files are scanned for
# identifiers only, because they cannot execute.  Any other suffix is unsupported.
_LANGUAGE_BY_SUFFIX = {".cjs": "javascript", ".js": "javascript", ".mjs": "javascript", ".py": "python"}
_DATA_SUFFIXES = frozenset({".csv", ".json", ".md", ".toml", ".txt"})
_DYNAMIC_PATTERNS: dict[str, tuple[str, ...]] = {
    "javascript": (
        r"\b(?:eval|Function)\s*\(", r"\bnew\s+Function\b", r"\bimport\s*\(", r"\brequire\s*\(",
        r"\bReflect\s*\.", r"\bglobalThis\b", r"\bProxy\s*\(", r"__proto__", r"\bcreateRequire\b",
        r"\bprocess\s*\.\s*binding\b", r"\bvm\s*\.",
    ),
    "python": (
        r"__import__", r"\bimportlib\b", r"\b(?:eval|exec|compile|getattr|setattr|delattr|globals|locals|vars)\s*\(",
        r"__dict__", r"__getattribute__", r"__subclasses__", r"__builtins__",
        r"\bsys\s*\.\s*modules\b", r"\bctypes\b", r"\b(?:marshal|pickle|runpy|shelve)\b",
    ),
}
_EXTERNAL_PATTERNS: dict[str, tuple[str, ...]] = {
    "javascript": (
        r"\bchild_process\b", r"\b(?:spawn|fork|exec|execFile\w*)\s*\(", r"\bfetch\s*\(", r"\bWebSocket\b",
        r"\bnode:(?:child_process|cluster|dgram|dns|http|https|net|tls|worker_threads)\b",
    ),
    "python": (
        r"\bsubprocess\b", r"\bos\s*\.\s*(?:system|popen|exec\w*|spawn\w*|fork\w*)\b",
        r"\bmultiprocessing\b", r"\bsocket\b", r"\burllib\b", r"\bhttp\s*\.\s*client\b",
        r"\b(?:httpx|requests|ftplib|smtplib|sqlite3)\b", r"\basyncio\s*\.\s*create_subprocess\w*",
    ),
}

# Identifier matching is wider than an exact whole-word search, so a spelling variant
# cannot hide a registered boundary reference.  Text is NFKC-normalized and format
# characters are dropped first.  A token may carry leading underscores (a private
# name), its words may be joined by an optional underscore and case-folded (camel,
# Pascal and upper snake), and it may take a plural ``s`` or ``es``.  Every variant
# counts as a reference, which keeps the contradiction conservative.  A distinct
# longer word (``unappend_x``, ``x_count``) is not a variant.
_IDENTIFIER_NORMALIZATION = "NFKC"
_IDENTIFIER_STRIPPED_CATEGORY = "Cf"
_IDENTIFIER_PREFIX = r"(?<![A-Za-z0-9_])_*"
_IDENTIFIER_WORD_JOIN = "_?"
_IDENTIFIER_SUFFIX = r"(?:e?s)?(?![A-Za-z0-9_])"
_IDENTIFIER_FLAGS = re.IGNORECASE

# Digest of each registered definition, pinned in source so an edit to the
# registry, the shared gates or the algorithm is a visible change that fails closed.
# Regenerate only with an explicit, reviewed change to the definition itself.
_PINNED_CLOSURE_DIGESTS: dict[str, str] = {
    # Original-kind pins are populated beside the consequential-kind pins so a
    # source edit cannot silently change what a fresh DOES_NOT_APPLY run means.
    "HUMAN": "sha256:b8bbe5ff94538b50d4e0467f8b5f4ccfa19ec30a32252d918d30622e401f4dc3",
    "ACTOR": "sha256:2e5de289b8d4e9f7400bda4be2576a0bc908008f1454112708699d82b5531b96",
    "COLLECTIVE": "sha256:c814e635d170e8776c4ee7dca30e36c32517f88d1cb0bb89107a321fa9397c00",
    "ROLE": "sha256:2ef6c5fade37145c95af5cbe8a326541278535a4b15f10d44344bb3f8506fa4e",
    "IDENTITY": "sha256:7dc60d5393224fe796613fa09e039749252053a480b3ba7a17254fc2c28a25a2",
    "OWNER": "sha256:10188da4ec4e955409b5dff07b14a3f46c89e8be4ba2142cea616f04410ed742",
    "HARDWARE": "sha256:92506f82a2330c5390f3da3a526d47931185b2ed6b546482f26104c49cc4beb6",
    "RECEIPT": "sha256:3c6be9ecfafae436ea083a8f61d27c4706e9abc31af2c3ab408a8a031bf35cba",
    "OBJECT": "sha256:f0a0b89b5817cc5c72e691975890a1b427b9097e4a7cbdde6bcf7f704dd1cdd4",
    "GRAPH": "sha256:756bdddfba8f894b7990cbc90106dbd21d04c6501dfecb47058e72830b64c7ba",
    "SPACE": "sha256:21312a43ab633927cf9f57c229f29ef11b6d02dd22e2ac655abcfee9c1d6fdfa",
    "TIME": "sha256:112be21cc4ea8bfbbb89e96cda375ce470113172feea60b74bd20f3c9bb24056",
    "EVENT": "sha256:feeba87331554d03ffaa6ac260f8454efe4e4a3cf3deeee7bffb98554babf3da",
    "ENV": "sha256:5fc2a702eefae382437a177a025ba14aa706d0a67765048b92cc367edb311747",
    "DATA": "sha256:343a0be35f112a3a49afb86508f79cbaa07234c79193a9f8ac8f0044b3636960",
    "VERIFIER": "sha256:6576f4dd7d3370c2709d9b7e72239a13a7deadcec13ae3172cc5fac0ab309b2f",
    "BENCH": "sha256:3a906f1d1abe52ee25f605fdce133b8902fca48a7d9466a4a651b5ef4f826e0b",
    "ARCH": "sha256:894c23fbf695092e9baf4607bf7cfb81ff0a4579020d606a249cf076a256977c",
    "TRAIN": "sha256:9cd54c27264bc0f051cd3a06db62a57010b5ab55bb178146768147476c6ebe3d",
    "HYPER": "sha256:ac51cdb18309a81a0c5d6e0c7d1e539cc5bcb0606e6aae1bf5948ccf6cdaa008",
    "MODEL": "sha256:9949976b39d7e7391ad54d6016d2bc9a1100dbfdbff13f7d0c0e623f3a279cb6",
    "HARNESS": "sha256:0c61527e302931dcba2d31448009ffa6caff374a6e16ec64d5421c71286b1b37",
    "AGENT": "sha256:905b66fd9283d1f80898d0ab540e9d3c6b833dbf4ec490e0d9316305894a4427",
    "SIM": "sha256:71472b3060e4a49d463a8e909968523f0bc8dcff0aad2a53667dc05a076ddaf6",
    "BOT": "sha256:262f9403edc7ba9ba39e8a289b83d6618afaf1c4b5ea6876d94b9b52d60dada8",
    "TOKEN": "sha256:aad7bcce5c60a2de523d655ca5bd001272e9e62bfb51b53a6097e10821725f9a",
    "LEDGER": "sha256:f7e15b341fd6e86cddceedb993a0ebc6b6a01c5b5943e9ba26c83193111cb082",
    "TRANSACTION": "sha256:e53f3c7ce339edd0bf06bd195e7853c5baa6dc7fff9c6a27f1b0ee0c20638cee",
    "ASSET": "sha256:51657a6fe99a1491072b6210e586912cdcecfea7d34e0f657d75d7ba230fdef2",
    "MARKET": "sha256:7888cac60247b67103e55687be0b63787d71a70a799223a88b45504522fafc97",
    "MEASUREMENT": "sha256:2f0137a6686fc765dee0d7e73ac5ea71c063e04e2cd2a7e2b7ab6517307c6507",
    "SENSOR": "sha256:6a1ea93753af71b34981e80776a548be50e1e8d4067e3e18349ebf86222de3dc",
    "CONTROLLER": "sha256:dd0984c3590f5c5c23c79ac7da435b3ac0a6c9af4000d7ad36fde3a6b2729d4a",
    "ACTUATOR": "sha256:676ebd7238bfca8b3881bb3dfe01feae6578e6bc1006e19c2c5f68dc529fc1ac",
    "PROTOCOL": "sha256:9deb887fd9556fb2f8b98ecd7287d866486f1d78b832d4ada749f27e20c68eb5",
    "POLICY": "sha256:3dbb152d205618d1c806b9aac30cab415d3587d8831a80b73ec8f37326fd2114",
    "ROBOT": "sha256:cb1a3ff30c3af7f6f3d75afda95da6e521d85a080c04c8c6599749f787a2dab5",
    "FINBOT": "sha256:14a3e5b7829202fdb6da1f9874b37447d5f89c30cf3af6e9c27934f20ff1ef4d",
}


@dataclasses.dataclass(frozen=True)
class Verdict:
    status: str
    code: str
    detail: str
    # Present only on a verdict produced by a fresh closure run.
    receipt: dict[str, Any] | None = None

    @property
    def is_established(self) -> bool:
        return self.status == ESTABLISHED


class WitnessBuildError(ValueError):
    """Raised when inputs cannot be bound into a witness; carries a stable code."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code + (": " + detail if detail else ""))
        self.code = code
        self.detail = detail


def canonical_bytes(value: Any) -> bytes:
    """Stable JavaScript Object Notation (JSON) bytes; identical to tier_zero_profile for ASCII-only values."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def value_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _closure_definition(kind: str, closure: Closure) -> dict[str, Any]:
    return {"algorithm": CLOSURE_ALGORITHM, "claim": closure.claim,
            "closure_id": closure.closure_id, "data_suffixes": sorted(_DATA_SUFFIXES),
            "dynamic_patterns": {name: list(patterns) for name, patterns in sorted(_DYNAMIC_PATTERNS.items())},
            "encoding": "utf-8", "external_patterns": {name: list(patterns)
                                                      for name, patterns in sorted(_EXTERNAL_PATTERNS.items())},
            "gate_lexing": {"python": _PYTHON_GATE_LEXING},
            "identifier_matching": {"flags": int(_IDENTIFIER_FLAGS), "normalization": _IDENTIFIER_NORMALIZATION,
                                    "prefix": _IDENTIFIER_PREFIX, "stripped_category": _IDENTIFIER_STRIPPED_CATEGORY,
                                    "suffix": _IDENTIFIER_SUFFIX, "word_join": _IDENTIFIER_WORD_JOIN},
            "identifiers": sorted(closure.identifiers), "kind": kind,
            "languages": dict(sorted(_LANGUAGE_BY_SUFFIX.items())),
            "scope": "OWNED_CENSUS_AND_CALLEE_ANCHORS"}


def closure_claim(kind: str) -> str | None:
    """The exact claim a registered closure supports, or ``None`` if unregistered.

    A clean scan supports only this text, never establishment of non-applicability.
    """
    closure = _CLOSURES.get(kind)
    return None if closure is None else closure.claim


def _limits() -> dict[str, Any]:
    """Bounds in effect for one run; bound into every receipt, outside the pinned definition."""
    return {"max_anchor_bytes": MAX_ANCHOR_BYTES, "max_callee_anchors": MAX_CALLEE_ANCHORS,
            "max_closure_bytes": MAX_CLOSURE_BYTES, "max_closure_seconds": MAX_CLOSURE_SECONDS,
            "max_detail_bytes": _MAX_DETAIL, "max_source_anchors": MAX_SOURCE_ANCHORS}


def closure_digest(kind: str) -> str | None:
    """Digest of the registered definition for ``kind``, or ``None`` if unregistered."""
    closure = _CLOSURES.get(kind)
    if closure is None:
        return None
    return value_digest(_closure_definition(kind, closure))


def build_witness(*, expected: ExpectedReview, source_paths, callee_paths=(), inventory) -> dict[str, Any]:
    """Bind already-established anchors into a witness document.

    Digests come only from the explicit inventory, so a caller cannot supply
    anchor digests.  The transitive callee closure is bound as given; this
    function does not compute or verify it.
    """
    problem = _expected_verdict(expected)
    if problem is not None:
        raise WitnessBuildError(problem.code, problem.detail)
    problem = _inventory_verdict(inventory)
    if problem is not None:
        raise WitnessBuildError(problem.code, problem.detail)
    if type(source_paths) not in (list, tuple) or type(callee_paths) not in (list, tuple):
        raise WitnessBuildError("MALFORMED_FIELD", "anchor paths must be list or tuple")
    if not source_paths:
        raise WitnessBuildError("MISSING_SOURCE_ANCHOR")
    if len(source_paths) > MAX_SOURCE_ANCHORS or len(callee_paths) > MAX_CALLEE_ANCHORS:
        raise WitnessBuildError("OVERSIZE", "anchor count")
    sources = [_builder_anchor(path, True, expected, inventory) for path in source_paths]
    callees = [_builder_anchor(path, False, expected, inventory) for path in callee_paths]
    folded = [anchor["path"].casefold() for anchor in sources + callees]
    if len(set(folded)) != len(folded):
        raise WitnessBuildError("DUPLICATE_ANCHOR")
    body = {
        "schema": SCHEMA,
        "object_id": expected.object_id,
        "kind": expected.kind,
        "decision_status": DECISION_STATUS,
        "basis": expected.basis,
        "review_module": expected.review_module,
        "review_mechanism_digest": expected.review_mechanism_digest,
        "review_row_digest": expected.review_row_digest,
        "source_anchors": sorted(sources, key=_anchor_path),
        "callee_anchors": sorted(callees, key=_anchor_path),
    }
    document = dict(body)
    document["witness_digest"] = value_digest(body)
    if len(canonical_bytes(document)) > MAX_WITNESS_BYTES:
        raise WitnessBuildError("OVERSIZE", "witness bytes")
    check = validate_dne_witness(document, expected=expected, inventory=inventory)
    # A bound executable witness is awaiting its fresh run, which is not a failure.
    if not (check.status == AUDITED_NOT_ESTABLISHED or check.code == "EXECUTION_NOT_RUN"):
        raise WitnessBuildError("SELF_CHECK_FAILED", check.code)
    return document


def validate_dne_witness(document: Any, *, expected: Any, inventory: Any) -> Verdict:
    """Validate a witness document against explicit expected identity and inventory.

    Never raises for malformed input.  Checks run in a fixed order: expected
    identity, inventory, shape and bounds, digest integrity, identity, and anchor
    currency.  FAIL outranks UNKNOWN when both are present.

    An executable witness that passes every check returns UNKNOWN with code
    EXECUTION_NOT_RUN.  That is binding only; it is never ESTABLISHED.
    """
    if expected is None:
        return Verdict(UNKNOWN, "EXPECTED_ABSENT", "")
    problem = _expected_verdict(expected)
    if problem is not None:
        return problem
    if inventory is None:
        return Verdict(UNKNOWN, "INVENTORY_ABSENT", "")
    problem = _inventory_verdict(inventory)
    if problem is not None:
        return problem
    if document is None:
        return Verdict(UNKNOWN, "WITNESS_ABSENT", "")
    problem = _shape_verdict(document)
    if problem is not None:
        return problem
    if document["witness_digest"] != value_digest(_body(document)):
        return Verdict(FAIL, "DIGEST_MISMATCH", "witness_digest")
    problem = _identity_verdict(document, expected)
    if problem is not None:
        return problem
    return _currency_verdict(document, expected, inventory)


def establish_dne_witness(document: Any, *, expected: Any, inventory: Any,
                          read: Callable[[str], bytes] | None) -> Verdict:
    """Judge a fresh registered closure run; a clean run is bounded, never established.

    Binding and currency are checked first.  The closure then runs over bytes
    returned by ``read`` for the exact anchored census, and its receipt is judged
    against the same identity.  A clean run is UNKNOWN with BOUNDED_ABSENCE_CODE and
    keeps its receipt.  A boundary reference is FAIL.  Every other outcome is UNKNOWN.
    No installed closure returns ESTABLISHED.
    """
    static = validate_dne_witness(document, expected=expected, inventory=inventory)
    if static.code != "EXECUTION_NOT_RUN":
        return static
    if read is None:
        return Verdict(UNKNOWN, "READER_ABSENT", "no source reader for the fresh closure run")
    receipt = run_closure(expected=expected, document=document, inventory=inventory, read=read)
    return _judge_receipt(receipt, document=document, expected=expected, inventory=inventory)


class _Refusal(Exception):
    """Internal: stops one closure run with a stable UNKNOWN code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def run_closure(*, expected: ExpectedReview, document: dict[str, Any],
                inventory: dict[str, Any], read: Callable[[str], bytes]) -> dict[str, Any]:
    """Run the registered closure now over a witness's anchored census and return a typed receipt.

    Work is bounded by byte budgets, and the scanner's wall-clock time is checked
    afterwards.  The run cannot preempt itself, so a scanner that overruns its
    time is discarded as EXECUTION_TIMEOUT.  Nothing is cached between calls.
    """
    started = time.monotonic()
    anchors = _document_anchors(document)
    owned = {path for path, entry in inventory.items() if entry["owner"] == expected.review_module}
    partial = not owned <= {anchor["path"] for anchor in anchors}
    return _closure_receipt(expected, anchors, inventory, read, started=started, partial=partial)


@dataclasses.dataclass(frozen=True)
class _CensusIdentity:
    """The identity a census receipt binds; field names match ``ExpectedReview``."""

    object_id: str
    kind: str
    review_row_digest: str
    review_mechanism_digest: str


def judge_census_closure(*, object_id: Any, kind: Any, decision_row_digest: Any, mechanism_digest: Any,
                         census: Any, read: Callable[[str], bytes] | None,
                         memo: dict[Any, Any] | None = None) -> Verdict:
    """Run the registered closure for ``kind`` now over an object's exact current owned census.

    No witness is stored or read, so nothing can be stale or forged in the manifest.  The
    caller supplies every owned path with its digest from the current source census; each
    byte read is checked against that digest before it is scanned, and the receipt binds the
    object, kind, decision row, mechanism, closure definition, limits and census.  The census
    is bounded by the receipt's anchor limit.  A clean run is UNKNOWN with BOUNDED_ABSENCE_CODE
    and keeps its receipt, exactly as for a witness, so this alone never admits anything.  A
    registered boundary reference is UNKNOWN, not FAIL: no reviewer asserted that this census
    scans clean, so a mention is a reason to review, not a contradiction of a bound claim.
    ``memo`` may carry normalized text and gate outcomes between runs over the same bytes;
    entries are keyed by path and verified digest, so it can never serve other bytes.
    """
    if not (_text(object_id, _OBJECT_RE, _MAX_IDENTIFIER) and _text(kind, _KIND_RE, _MAX_KIND)
            and _is_digest(decision_row_digest) and _is_digest(mechanism_digest)):
        return _v(UNKNOWN, "REVIEW_IDENTITY_UNBINDABLE", "")
    if type(census) is not dict or not all(type(path) is str for path in census):
        return _v(UNKNOWN, "CENSUS_MALFORMED", "")
    if not census:
        return _v(UNKNOWN, "CENSUS_EMPTY", "")
    if len(census) > MAX_SOURCE_ANCHORS + MAX_CALLEE_ANCHORS:
        return _v(UNKNOWN, "OVERSIZE", "census anchor count")
    folded: set[str] = set()
    for path in sorted(census):
        if _path_code(path) is not None:
            return _v(UNKNOWN, "CENSUS_PATH_UNBINDABLE", path[:_MAX_DETAIL])
        if path == MANIFEST_PATH:
            return _v(UNKNOWN, "SELF_REFERENTIAL_CENSUS", MANIFEST_PATH)
        if not _is_digest(census[path]):
            return _v(UNKNOWN, "CENSUS_DIGEST_MALFORMED", path[:_MAX_DETAIL])
        if path.casefold() in folded:
            return _v(UNKNOWN, "DUPLICATE_ANCHOR", path[:_MAX_DETAIL])
        folded.add(path.casefold())
    if read is None:
        return _v(UNKNOWN, "READER_ABSENT", "no source reader for the fresh closure run")
    started = time.monotonic()
    identity = _CensusIdentity(object_id, kind, decision_row_digest, mechanism_digest)
    anchors = [{"path": path, "sha256": census[path]} for path in sorted(census)]
    inventory = {anchor["path"]: {"sha256": anchor["sha256"]} for anchor in anchors}
    receipt = _closure_receipt(identity, anchors, inventory, read, started=started, memo=memo)
    verdict = _judge_receipt(receipt, document={"source_anchors": anchors, "callee_anchors": []},
                             expected=identity, inventory=inventory)
    if verdict.status == FAIL and verdict.code == REFERENCE_CODE:
        return Verdict(UNKNOWN, verdict.code, verdict.detail, receipt=verdict.receipt)
    return verdict


def _closure_receipt(identity: ExpectedReview | _CensusIdentity, anchors: list[dict[str, str]],
                     inventory: dict[str, Any], read: Callable[[str], bytes], *, started: float,
                     partial: bool = False, memo: dict[Any, Any] | None = None) -> dict[str, Any]:
    """Run the registered, pinned closure of ``identity.kind`` over exact anchors."""
    closure = _CLOSURES.get(identity.kind)
    if closure is None:
        return _receipt(identity, None, anchors, CLOSURE_UNKNOWN, "CLOSURE_UNREGISTERED", "")
    if closure_digest(identity.kind) != _PINNED_CLOSURE_DIGESTS.get(identity.kind):
        return _receipt(identity, closure, anchors, CLOSURE_UNKNOWN, "CLOSURE_PIN_MISMATCH", "")
    if partial:
        return _receipt(identity, closure, anchors, CLOSURE_UNKNOWN, "PARTIAL_CENSUS", "")
    try:
        texts = _read_anchored_text(anchors, inventory, read)
        if memo is None:
            status, code, detail = _scan_boundary_references(closure, texts)
        else:
            digests = {anchor["path"]: anchor["sha256"] for anchor in anchors}
            status, code, detail = _scan_boundary_references(closure, texts, memo=memo, digests=digests)
    except _Refusal as refusal:
        return _receipt(identity, closure, anchors, CLOSURE_UNKNOWN, refusal.code, "")
    except TimeoutError:
        return _receipt(identity, closure, anchors, CLOSURE_UNKNOWN, "EXECUTION_TIMEOUT", "")
    except Exception:  # The closure reports its own fault; no exception text is trusted.
        return _receipt(identity, closure, anchors, CLOSURE_UNKNOWN, "EXECUTION_ERROR", "")
    if time.monotonic() - started > MAX_CLOSURE_SECONDS:
        return _receipt(identity, closure, anchors, CLOSURE_UNKNOWN, "EXECUTION_TIMEOUT", "")
    return _receipt(identity, closure, anchors, status, code, detail)


def _read_anchored_text(anchors: list[dict[str, str]], inventory: dict[str, Any],
                        read: Callable[[str], bytes]) -> list[tuple[str, str]]:
    """Read each anchor, prove it matches the census, and decode it as Unicode Transformation Format, 8-bit (UTF-8)."""
    texts: list[tuple[str, str]] = []
    total = 0
    for anchor in anchors:
        try:
            data = read(anchor["path"])
        except OSError as exc:
            raise _Refusal("SOURCE_UNREADABLE") from exc
        if type(data) is not bytes:
            raise _Refusal("SOURCE_UNREADABLE")
        if len(data) > MAX_ANCHOR_BYTES:
            raise _Refusal("OVERSIZE")
        total += len(data)
        if total > MAX_CLOSURE_BYTES:
            raise _Refusal("BUDGET_EXCEEDED")
        if "sha256:" + hashlib.sha256(data).hexdigest() != inventory[anchor["path"]]["sha256"]:
            raise _Refusal("STALE_SOURCE")
        try:
            texts.append((anchor["path"], data.decode("utf-8")))
        except UnicodeDecodeError as exc:
            raise _Refusal("SOURCE_UNDECODABLE") from exc
    return texts


def _scan_boundary_references(closure: Closure, texts: list[tuple[str, str]], *,
                              memo: dict[Any, Any] | None = None,
                              digests: dict[str, str] | None = None) -> tuple[str, str, str]:
    """Return FAIL on any boundary identifier, then UNKNOWN on any gate hit, else PASS.

    A boundary reference is a contradiction and outranks every gate.  The gates
    run only after the whole census is free of references, so an unresolved
    construct can never hide a refuting reference in another file.  Both scans see
    the same normalized text, so a spelling variant cannot pass one and fail the other.
    With ``memo`` and ``digests`` together, normalized text and gate outcomes are kept
    per path and digest of the bytes already verified for that path; neither depends on
    the kind, so one file is normalized and gated once across every kind's run.
    """
    pattern = _identifier_pattern(closure.identifiers)
    prepared = [(path, _remembered(memo, digests, "text", path, _normalized_for_scan, text))
                for path, text in texts]
    for path, text in prepared:
        match = pattern.search(text)
        if match is not None:
            return CLOSURE_FAIL, REFERENCE_CODE, (path + " references " + match.group(0))[:_MAX_DETAIL]
    for path, text in prepared:
        hit = _remembered(memo, digests, "gate", path, _gate_hit, path, text)
        if hit is not None:
            return CLOSURE_UNKNOWN, hit[0], hit[1]
    return CLOSURE_PASS, PASS_CODE, ""


def _remembered(memo: dict[Any, Any] | None, digests: dict[str, str] | None, tag: str, path: str,
                compute: Callable[..., Any], *args: Any) -> Any:
    """Return ``compute(*args)``; with a memo, keep it per tag, path and verified digest."""
    if memo is None or digests is None:
        return compute(*args)
    key = (tag, path, digests[path])
    if key not in memo:
        memo[key] = compute(*args)
    return memo[key]


def _gate_hit(path: str, text: str) -> tuple[str, str] | None:
    """Return the first shared-gate hit, as (code, detail), for one normalized census file."""
    language = _language_of(path)
    if language is None:
        return "UNSUPPORTED_LANGUAGE", path[:_MAX_DETAIL]
    if language == "data":
        return None
    gate_text = _python_gate_text(text) if language == "python" else text
    for code, patterns in (("DYNAMIC_FEATURE_PRESENT", _DYNAMIC_PATTERNS[language]),
                           ("EXTERNAL_EFFECT_PRESENT", _EXTERNAL_PATTERNS[language])):
        for source in patterns:
            hit = re.search(source, gate_text)
            if hit is not None:
                return code, (path + " uses " + hit.group(0))[:_MAX_DETAIL]
    return None


def _python_gate_text(text: str) -> str:
    """Mask inert Python prose before dynamic/external-effect gate matching.

    Boundary identifiers still scan the complete normalized source because a
    string may be an operational registry key. Shared effect gates instead ask
    whether executable Python syntax names a dynamic or external mechanism.
    Comments, docstrings, and ordinary string constants are not such syntax.
    Formatted strings remain visible because their expressions can execute.  The
    exact qualified call ``re.compile(...)`` is also masked: it compiles a regular
    expression, not Python code.  Unqualified ``compile(...)`` and every other
    spelling remain fail-closed dynamic-code hits.
    If tokenization cannot establish the lexical boundary, retain the original
    text so the gate fails closed.
    """

    lines = text.splitlines(keepends=True)
    offsets: list[int] = []
    cursor = 0
    for line in lines:
        offsets.append(cursor)
        cursor += len(line)
    if not lines or cursor < len(text):
        offsets.append(cursor)
    masked = list(text)
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        significant: list[tokenize.TokenInfo] = []
        for item in tokens:
            if item.type == tokenize.COMMENT:
                should_mask = True
            elif item.type == tokenize.STRING:
                prefix = re.match(r"(?i)^([rubf]*)", item.string)
                should_mask = prefix is not None and "f" not in prefix.group(1).lower()
            elif (item.type == tokenize.NAME and item.string == "compile" and
                  len(significant) >= 2 and significant[-1].type == tokenize.OP and
                  significant[-1].string == "." and significant[-2].type == tokenize.NAME and
                  significant[-2].string == "re"):
                should_mask = True
            else:
                should_mask = False
            if should_mask:
                start_row, start_column = item.start
                end_row, end_column = item.end
                start = offsets[start_row - 1] + start_column
                end = offsets[end_row - 1] + end_column
                for index in range(start, end):
                    if masked[index] not in "\r\n":
                        masked[index] = " "
            if item.type not in {tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE,
                                 tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER}:
                significant.append(item)
                if len(significant) > 2:
                    significant.pop(0)
    except (IndentationError, SyntaxError, tokenize.TokenError):
        return text
    return "".join(masked)


def is_data_path(path: str) -> bool:
    """True when the shared gates treat ``path`` as inert data: scanned for identifiers, never executed."""
    return _language_of(path) == "data"


def _normalized_for_scan(text: str) -> str:
    """NFKC-normalize and drop format characters so spelling variants meet one scan."""
    folded = unicodedata.normalize(_IDENTIFIER_NORMALIZATION, text)
    return "".join(char for char in folded if unicodedata.category(char) != _IDENTIFIER_STRIPPED_CATEGORY)


def _identifier_pattern(identifiers: frozenset[str]) -> re.Pattern:
    """One variant-aware alternation over every identifier, so none is registry-first-only."""
    alternatives = "|".join(
        _IDENTIFIER_WORD_JOIN.join(re.escape(word) for word in name.split("_"))
        for name in sorted(identifiers))
    return re.compile(_IDENTIFIER_PREFIX + "(?:" + alternatives + ")" + _IDENTIFIER_SUFFIX, _IDENTIFIER_FLAGS)


def _language_of(path: str) -> str | None:
    """Return the gate language for a census path, ``data`` for inert text, or ``None``."""
    name = path.rsplit("/", 1)[-1]
    dot = name.rfind(".")
    if dot <= 0:
        return None
    suffix = name[dot:]
    if suffix in _DATA_SUFFIXES:
        return "data"
    return _LANGUAGE_BY_SUFFIX.get(suffix)


def _receipt(expected: ExpectedReview | _CensusIdentity, closure: Closure | None, anchors: list[dict[str, str]],
             status: str, code: str, detail: str) -> dict[str, Any]:
    body = {
        "schema": CLOSURE_SCHEMA,
        "object_id": expected.object_id,
        "kind": expected.kind,
        "closure_id": closure.closure_id if closure is not None else None,
        "closure_digest": closure_digest(expected.kind),
        "decision_row_digest": expected.review_row_digest,
        "mechanism_digest": expected.review_mechanism_digest,
        "limits_digest": value_digest(_limits()),
        "anchors": anchors,
        "census_digest": value_digest(anchors),
        "status": status,
        "code": code,
        "detail": detail,
    }
    return {**body, "receipt_digest": value_digest(body)}


def _receipt_body(receipt: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in receipt.items() if key != "receipt_digest"}


def _judge_receipt(receipt: Any, *, document: dict[str, Any], expected: ExpectedReview | _CensusIdentity,
                   inventory: dict[str, Any]) -> Verdict:
    """Accept a receipt only when it is well formed, self-consistent and bound now."""
    problem = _receipt_shape(receipt)
    if problem is not None:
        return _v(FAIL, "RECEIPT_MALFORMED", problem)
    if receipt["receipt_digest"] != value_digest(_receipt_body(receipt)):
        return _v(FAIL, "RECEIPT_DIGEST_MISMATCH", "receipt_digest")
    if receipt["census_digest"] != value_digest(receipt["anchors"]):
        return _v(FAIL, "RECEIPT_DIGEST_MISMATCH", "census_digest")
    identity = (
        ("object_id", expected.object_id),
        ("kind", expected.kind),
        ("decision_row_digest", expected.review_row_digest),
        ("mechanism_digest", expected.review_mechanism_digest),
        ("closure_digest", closure_digest(expected.kind)),
        ("limits_digest", value_digest(_limits())),
    )
    for field, value in identity:
        if receipt[field] != value:
            return _v(FAIL, "RECEIPT_REPLAYED", field)
    if receipt["closure_id"] != (_CLOSURES[expected.kind].closure_id if expected.kind in _CLOSURES else None):
        return _v(FAIL, "RECEIPT_REPLAYED", "closure_id")
    if receipt["anchors"] != _document_anchors(document):
        return _v(UNKNOWN, "RECEIPT_STALE", "anchored census changed since the closure was bound")
    for anchor in receipt["anchors"]:
        if inventory.get(anchor["path"], {}).get("sha256") != anchor["sha256"]:
            return _v(UNKNOWN, "RECEIPT_STALE", anchor["path"])
    if receipt["status"] == CLOSURE_PASS:
        if receipt["code"] != PASS_CODE or receipt["detail"] != "":
            return _v(FAIL, "RECEIPT_MALFORMED", "pass_code")
        # A finite scan that finds nothing supports only a bounded observation.  No
        # installed closure may establish: absence of listed spellings is not
        # non-applicability, so the fresh receipt is kept and the verdict stays non-admissible.
        return Verdict(UNKNOWN, BOUNDED_ABSENCE_CODE, receipt["closure_id"], receipt=receipt)
    if receipt["status"] == CLOSURE_FAIL:
        if receipt["code"] != REFERENCE_CODE:
            return _v(FAIL, "RECEIPT_MALFORMED", "fail_code")
        return Verdict(FAIL, receipt["code"], receipt["detail"], receipt=receipt)
    return Verdict(UNKNOWN, receipt["code"], receipt["detail"], receipt=receipt)


def _receipt_shape(receipt: Any) -> str | None:
    if type(receipt) is not dict or set(receipt) != RECEIPT_KEYS:
        return "keys"
    if receipt["schema"] != CLOSURE_SCHEMA:
        return "schema"
    if type(receipt["status"]) is not str or receipt["status"] not in CLOSURE_STATUSES:
        return "status"
    for field in ("object_id", "closure_id"):
        if receipt[field] is not None and not _text(receipt[field], _OBJECT_RE, _MAX_IDENTIFIER):
            return field
    if not _text(receipt["object_id"], _OBJECT_RE, _MAX_IDENTIFIER):
        return "object_id"
    if not _text(receipt["kind"], _KIND_RE, _MAX_KIND):
        return "kind"
    if type(receipt["code"]) is not str or _TOKEN_RE.fullmatch(receipt["code"]) is None:
        return "code"
    if type(receipt["detail"]) is not str or len(receipt["detail"]) > _MAX_DETAIL:
        return "detail"
    for field in ("closure_digest", "decision_row_digest", "mechanism_digest", "limits_digest",
                  "census_digest", "receipt_digest"):
        if receipt[field] is not None and not _is_digest(receipt[field]):
            return field
    if type(receipt["anchors"]) is not list or len(receipt["anchors"]) > MAX_SOURCE_ANCHORS + MAX_CALLEE_ANCHORS:
        return "anchors"
    for anchor in receipt["anchors"]:
        if type(anchor) is not dict or set(anchor) != _ANCHOR_KEYS:
            return "anchors"
        if _path_code(anchor["path"]) is not None or not _is_digest(anchor["sha256"]):
            return "anchors"
    return None


def _document_anchors(document: dict[str, Any]) -> list[dict[str, str]]:
    return sorted(
        [{"path": anchor["path"], "sha256": anchor["sha256"]}
         for anchor in document["source_anchors"] + document["callee_anchors"]],
        key=_anchor_path)


def _v(status: str, code: str, detail: str = "") -> Verdict:
    return Verdict(status, code, detail)


def _text(value: Any, pattern: re.Pattern, limit: int) -> bool:
    return type(value) is str and len(value) <= limit and pattern.fullmatch(value) is not None


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_RE.fullmatch(value) is not None


def _path_code(value: Any) -> str | None:
    if type(value) is not str:
        return "MALFORMED_PATH"
    if len(value) > MAX_PATH_BYTES:
        return "OVERSIZE"
    if _PATH_RE.fullmatch(value) is None:
        return "MALFORMED_PATH"
    if any(segment.split(".")[0].casefold() in _RESERVED_NAMES for segment in value.split("/")):
        return "MALFORMED_PATH"
    return None


def _body(document: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key != "witness_digest"}


def _anchor_path(anchor: dict[str, Any]) -> str:
    return anchor["path"]


def _expected_verdict(expected: Any) -> Verdict | None:
    if type(expected) is not ExpectedReview:
        return _v(FAIL, "EXPECTED_MALFORMED", "type")
    if not _text(expected.object_id, _OBJECT_RE, _MAX_IDENTIFIER):
        return _v(FAIL, "EXPECTED_MALFORMED", "object_id")
    if not _text(expected.kind, _KIND_RE, _MAX_KIND):
        return _v(FAIL, "EXPECTED_MALFORMED", "kind")
    if type(expected.basis) is not str or expected.basis not in BASES:
        return _v(FAIL, "EXPECTED_MALFORMED", "basis")
    if not _text(expected.review_module, _MODULE_RE, _MAX_IDENTIFIER):
        return _v(FAIL, "EXPECTED_MALFORMED", "review_module")
    if not _is_digest(expected.review_mechanism_digest):
        return _v(FAIL, "EXPECTED_MALFORMED", "review_mechanism_digest")
    if not _is_digest(expected.review_row_digest):
        return _v(FAIL, "EXPECTED_MALFORMED", "review_row_digest")
    return None


def _inventory_verdict(inventory: Any) -> Verdict | None:
    if type(inventory) is not dict:
        return _v(FAIL, "INVENTORY_MALFORMED", "type")
    if len(inventory) > MAX_INVENTORY_ENTRIES:
        return _v(FAIL, "INVENTORY_OVERSIZE", "entries")
    folded: set[str] = set()
    for path, entry in inventory.items():
        if _path_code(path) is not None:
            return _v(FAIL, "INVENTORY_MALFORMED", "path")
        key = path.casefold()
        if key in folded:
            return _v(FAIL, "ALIASED_PATH", path)
        folded.add(key)
        if type(entry) is not dict or set(entry) != _INVENTORY_KEYS:
            return _v(FAIL, "INVENTORY_MALFORMED", "entry")
        if not _text(entry["owner"], _MODULE_RE, _MAX_IDENTIFIER):
            return _v(FAIL, "INVENTORY_MALFORMED", "owner")
        if not _is_digest(entry["sha256"]):
            return _v(FAIL, "INVENTORY_MALFORMED", "sha256")
        if type(entry["available"]) is not bool:
            return _v(FAIL, "INVENTORY_MALFORMED", "available")
    return None


def _shape_verdict(document: Any) -> Verdict | None:
    if type(document) is not dict:
        return _v(FAIL, "WITNESS_MALFORMED", "type")
    if not all(type(key) is str for key in document):
        return _v(FAIL, "WITNESS_MALFORMED", "key_type")
    keys = set(document)
    if keys - _WITNESS_KEYS:
        return _v(FAIL, "EXTRA_KEY", "top_level")
    if _WITNESS_KEYS - keys:
        return _v(FAIL, "MISSING_KEY", "top_level")
    if type(document["schema"]) is not str or document["schema"] != SCHEMA:
        return _v(FAIL, "MALFORMED_FIELD", "schema")
    if type(document["decision_status"]) is not str or document["decision_status"] != DECISION_STATUS:
        return _v(FAIL, "UNKNOWN_DECISION", "decision_status")
    if type(document["basis"]) is not str or document["basis"] not in BASES:
        return _v(FAIL, "UNKNOWN_BASIS", "basis")
    for field, pattern, limit in (("object_id", _OBJECT_RE, _MAX_IDENTIFIER), ("kind", _KIND_RE, _MAX_KIND),
                                  ("review_module", _MODULE_RE, _MAX_IDENTIFIER)):
        if not _text(document[field], pattern, limit):
            return _v(FAIL, "MALFORMED_FIELD", field)
    for field in ("review_mechanism_digest", "review_row_digest", "witness_digest"):
        if not _is_digest(document[field]):
            return _v(FAIL, "MALFORMED_DIGEST", field)
    for field in ("source_anchors", "callee_anchors"):
        if type(document[field]) is not list:
            return _v(FAIL, "MALFORMED_FIELD", field)
    sources, callees = document["source_anchors"], document["callee_anchors"]
    if not sources:
        return _v(FAIL, "MISSING_SOURCE_ANCHOR")
    if len(sources) > MAX_SOURCE_ANCHORS or len(callees) > MAX_CALLEE_ANCHORS:
        return _v(FAIL, "OVERSIZE", "anchor_count")
    identities = [id(anchor) for anchor in sources] + [id(anchor) for anchor in callees]
    if len(set(identities)) != len(identities):
        return _v(FAIL, "ALIASED_CONTAINER")
    for anchor in sources + callees:
        if type(anchor) is not dict or set(anchor) != _ANCHOR_KEYS:
            return _v(FAIL, "MALFORMED_ANCHOR")
        code = _path_code(anchor["path"])
        if code is not None:
            return _v(FAIL, code, "anchor_path")
        if not _is_digest(anchor["sha256"]):
            return _v(FAIL, "MALFORMED_DIGEST", "anchor_sha256")
    for anchor in sources + callees:
        if anchor["path"] == MANIFEST_PATH:
            return _v(FAIL, "SELF_REFERENTIAL_ANCHOR", MANIFEST_PATH)
    folded = [anchor["path"].casefold() for anchor in sources + callees]
    if len(set(folded)) != len(folded):
        return _v(FAIL, "DUPLICATE_ANCHOR")
    for group in (sources, callees):
        paths = [anchor["path"] for anchor in group]
        if paths != sorted(paths):
            return _v(FAIL, "WRONG_ORDER")
    if len(canonical_bytes(document)) > MAX_WITNESS_BYTES:
        return _v(FAIL, "OVERSIZE", "witness_bytes")
    return None


def _identity_verdict(document: dict[str, Any], expected: ExpectedReview) -> Verdict | None:
    if document["basis"] != expected.basis:
        return _v(FAIL, "BASIS_MISMATCH", "basis")
    if document["object_id"] != expected.object_id:
        return _v(FAIL, "WRONG_OBJECT", "object_id")
    if document["kind"] != expected.kind:
        return _v(FAIL, "WRONG_KIND", "kind")
    if document["review_module"] != expected.review_module:
        return _v(FAIL, "WRONG_REVIEW_MODULE", "review_module")
    if document["review_mechanism_digest"] != expected.review_mechanism_digest:
        return _v(FAIL, "WRONG_MECHANISM", "review_mechanism_digest")
    if document["review_row_digest"] != expected.review_row_digest:
        return _v(FAIL, "WRONG_ROW", "review_row_digest")
    return None


def _currency_verdict(document: dict[str, Any], expected: ExpectedReview, inventory: dict[str, Any]) -> Verdict:
    unknown: Verdict | None = None
    anchors = [(anchor, True) for anchor in document["source_anchors"]]
    anchors += [(anchor, False) for anchor in document["callee_anchors"]]
    for anchor, owned in anchors:
        path = anchor["path"]
        entry = inventory.get(path)
        if entry is None:
            unknown = unknown or _v(UNKNOWN, "ANCHOR_NOT_IN_INVENTORY", path)
            continue
        if owned and entry["owner"] != expected.review_module:
            return _v(FAIL, "WRONG_OWNER", path)
        if not entry["available"]:
            unknown = unknown or _v(UNKNOWN, "ANCHOR_UNAVAILABLE", path)
        elif entry["sha256"] != anchor["sha256"]:
            unknown = unknown or _v(UNKNOWN, "STALE_ANCHOR", path)
    if unknown is not None:
        return unknown
    if expected.basis == BASIS_EXECUTABLE_CLOSURE:
        return _v(UNKNOWN, "EXECUTION_NOT_RUN", "bound and current; only a fresh closure run can establish")
    return _v(AUDITED_NOT_ESTABLISHED, "AUDITED_SOURCE_NOT_EXECUTABLE",
              "documented review of current anchored source; no executable closure claimed")


def _builder_anchor(path: Any, owned: bool, expected: ExpectedReview, inventory: dict[str, Any]) -> dict[str, str]:
    code = _path_code(path)
    if code is not None:
        raise WitnessBuildError(code, "anchor_path")
    if path == MANIFEST_PATH:
        raise WitnessBuildError("SELF_REFERENTIAL_ANCHOR", MANIFEST_PATH)
    entry = inventory.get(path)
    if entry is None:
        raise WitnessBuildError("ANCHOR_NOT_IN_INVENTORY", path)
    if owned and entry["owner"] != expected.review_module:
        raise WitnessBuildError("WRONG_OWNER", path)
    if not entry["available"]:
        raise WitnessBuildError("ANCHOR_UNAVAILABLE", path)
    return {"path": path, "sha256": entry["sha256"]}
