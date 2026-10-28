# Terminology: Secure Hash Algorithm 256-bit (SHA-256).
"""Closed source-bound execution registry for Verifier Standard (VSTD).

Only named installed experiments run. Selections contain source references, never
commands, import names or operator-resource paths. JavaScript Object Notation
(JSON) observations bind fresh requests to exact object and collection bytes.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import inspect
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from types import CodeType, ModuleType
from typing import Any, Iterator

from verifier.core import owned_process
from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.runtime.tier_zero_profile import (
    applicability_declaration,
    applicability_digest,
    canonical_bytes,
    value_digest,
)
from verifier.runtime import package_execution_observation as observation


# Fixed local message exchange is a PROTOCOL role, not only a generic function.
__vstd_kinds__ = ("PROTOCOL",)

# Closed expected set of adapters whose checker must bind the executed request, so the
# objective echo cannot be self-consistent for another request. The dispatcher owns
# this set. A mechanism's ``CHECKER_CONTRACT`` declaration must agree with it, and the
# checker signature must match the contract exactly. Emptying this set does not
# downgrade an adapter: its request-accepting signature then fails validation.
REQUEST_BOUND_ADAPTERS = frozenset({"verifier-emulated-control-1"})
_WORKER_TIMEOUT_SECONDS = 30
_MAX_WORKER_TIMEOUT_SECONDS = 90
_CHECKER_TIMEOUT_SECONDS = 30
_CHECKER_OUTPUT_LIMIT = 65536
_CHECKER_SCHEMA = "verifier-package-checker-receipt-1"
_CHECKER_PARAMETERS = {
    "observations-only": ("coordinate", "observed"),
    "request-bound": ("coordinate", "observed", "request"),
}
_STANDARD_SUBPROCESS_RUN = subprocess.run
# Obligation classification rides on the raised exception. Protocol checks read the
# exception type name and text from ``execute_bound``, so those must stay unchanged.
_OBLIGATION_ATTRIBUTE = "vstd_obligation"
_SOURCE_PIN_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CLOSED_REASON = re.compile(r"PACKAGE_[A-Z0-9_]+\Z")


def _run_package_worker(
    command: list[str], child_parameters: dict[str, Any], private_temp: Path
) -> owned_process.OwnedProcessResult:
    """Launch through the owner, retaining the historical injected-run test seam.

    Production uses the shared Job Object/process-group primitive.  Existing
    transport tests replace the exact ``subprocess.run`` object after import;
    that trusted in-process seam is converted into the same typed result so the
    request-binding tests remain independent of operating-system process setup.
    """

    if subprocess.run is not _STANDARD_SUBPROCESS_RUN:
        completed = subprocess.run(command, **child_parameters)
        if type(completed.stdout) is not bytes or type(completed.stderr) is not bytes:
            raise ValueError("PACKAGE_EXECUTION_PARENT_STREAM_INVALID")
        stdout_overflowed = len(completed.stdout) > observation.OUTPUT_LIMIT
        stderr_overflowed = len(completed.stderr) > observation.STDERR_LIMIT
        return owned_process.OwnedProcessResult(
            status=(owned_process.STATUS_OUTPUT_CAP if stdout_overflowed or stderr_overflowed
                    else owned_process.STATUS_EXITED),
            cleanup=owned_process.CLEANUP_CONFIRMED,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            stdout_overflowed=stdout_overflowed,
            stderr_overflowed=stderr_overflowed,
        )
    return owned_process.run_owned_process(
        command,
        cwd=private_temp,
        environment=child_parameters["env"],
        stdin=child_parameters["input"],
        timeout_seconds=child_parameters["timeout"],
        stdout_limit=observation.OUTPUT_LIMIT,
        stderr_limit=observation.STDERR_LIMIT,
    )


def _run_package_checker(
    command: list[str], child_parameters: dict[str, Any], private_temp: Path
) -> owned_process.OwnedProcessResult:
    """Run the verdict checker in a separately owned fresh interpreter.

    This launcher is deliberately separate from the historical observation-worker
    injection seam above. Replacing ``subprocess.run`` to model an observation
    transport cannot replace the checker that interprets those observations.
    """

    return owned_process.run_owned_process(
        command,
        cwd=private_temp,
        environment=child_parameters["env"],
        stdin=child_parameters["input"],
        timeout_seconds=child_parameters["timeout"],
        stdout_limit=_CHECKER_OUTPUT_LIMIT,
        stderr_limit=observation.STDERR_LIMIT,
    )


def mechanisms() -> dict[str, ModuleType]:
    from verifier.runtime import (local_ledger_execution, manifest_write_execution,
        worker_protocol_execution, provenance_policy_execution, resource_measurement_execution,
        token_asset_execution, emulator_control_execution)
    modules = (local_ledger_execution, manifest_write_execution, worker_protocol_execution,
        provenance_policy_execution, resource_measurement_execution,
        token_asset_execution, emulator_control_execution)
    registered: dict[str, ModuleType] = {}
    for module in modules:
        identifier = getattr(module, "ADAPTER", None)
        if type(identifier) is not str or not identifier:
            raise ValueError("PACKAGE_EXECUTION_MECHANISM_ADAPTER_INVALID")
        # Two modules with one identifier would silently shadow each other in the dispatch.
        if identifier in registered:
            raise ValueError("PACKAGE_EXECUTION_MECHANISM_ADAPTER_DUPLICATED")
        registered[identifier] = module
    return registered


def _worker_timeout_seconds(module: ModuleType) -> int:
    """Resolve a closed adapter's finite outer deadline, never caller input.

    Most workers have one 30-second execution window.  A closed adapter may
    declare a larger compositional window when its fixed experiment contains
    sequential bounded child launches.  The dispatcher retains the absolute
    ceiling so a mechanism declaration cannot create an unbounded execution.
    """

    declared = getattr(module, "WORKER_TIMEOUT_SECONDS", _WORKER_TIMEOUT_SECONDS)
    if (type(declared) is not int or declared < 1
            or declared > _MAX_WORKER_TIMEOUT_SECONDS):
        raise ValueError("PACKAGE_EXECUTION_WORKER_TIMEOUT_DECLARATION_INVALID")
    return declared


def checker_contract(module: ModuleType) -> str:
    """Return the request-binding contract a mechanism checker must satisfy.

    The closed expected set decides the contract. A declared ``CHECKER_CONTRACT`` must
    agree with it, a request-bound adapter may not omit the declaration, and the
    checker signature must match exactly. Nothing defaults to the two-argument form
    after a call fails, so no TypeError fallback exists.
    """
    identifier = getattr(module, "ADAPTER", None)
    if type(identifier) is not str:
        raise ValueError("PACKAGE_EXECUTION_MECHANISM_ADAPTER_INVALID")
    contract = "request-bound" if identifier in REQUEST_BOUND_ADAPTERS else "observations-only"
    declared = getattr(module, "CHECKER_CONTRACT", None)
    if declared is None:
        if contract == "request-bound":
            raise ValueError("PACKAGE_EXECUTION_CHECKER_CONTRACT_OMITTED")
    elif declared != contract:
        raise ValueError("PACKAGE_EXECUTION_CHECKER_CONTRACT_DRIFT")
    try:
        parameters = tuple(inspect.signature(module.check_observations).parameters.values())
    except (AttributeError, TypeError, ValueError):
        raise ValueError("PACKAGE_EXECUTION_CHECKER_CONTRACT_DRIFT") from None
    shape = tuple((parameter.name, parameter.kind) for parameter in parameters)
    expected = tuple((name, inspect.Parameter.POSITIONAL_OR_KEYWORD)
                     for name in _CHECKER_PARAMETERS[contract])
    if shape != expected:
        raise ValueError("PACKAGE_EXECUTION_CHECKER_CONTRACT_DRIFT")
    return contract


def _declared_route(route: dict[str, Any], module: ModuleType) -> dict[str, Any]:
    """Project a mechanism route with its exact implementation trigger."""
    applicability = applicability_declaration(
        mode="CONDITIONAL",
        condition=(
            "The admitted object's exact owned source denominator contains the "
            f"installed {module.IMPLEMENTATION} implementation selected by this "
            "finite package-execution route."
        ),
        reason=(
            route["reason"]
            + " This implementation-specific proposition becomes necessary only for "
              "an object that owns the exact installed implementation; an unresolved "
              "ownership condition is not an exemption."
        ),
    )
    return {**route, "applicability": applicability,
            "applicability_digest": applicability_digest(applicability)}


def catalog() -> list[dict[str, Any]]:
    return [_declared_route(route, module)
            for module in mechanisms().values() for route in module.catalog()]


def implementation(mechanism: str) -> str:
    try:
        return mechanisms()[mechanism].IMPLEMENTATION
    except KeyError:
        raise ValueError("PACKAGE_EXECUTION_MECHANISM_UNREGISTERED") from None


def route_mechanism(route: dict[str, Any]) -> ModuleType | None:
    module = mechanisms().get(route.get("adapter"))
    if module is None:
        return None
    raw = module.catalog()
    declared = [_declared_route(candidate, module) for candidate in raw]
    # Mechanism-local callers historically pass the raw immutable route.  The
    # package-facing catalog adds applicability, and any supplied declaration
    # must match that canonical projection exactly.
    if route not in raw and route not in declared:
        raise ValueError("PACKAGE_EXECUTION_ROUTE_BINDING_DIFFERS")
    return module


def owns_route_implementation(declaration: dict[str, Any], route: dict[str, Any]) -> bool:
    """Decide the exact source-owned applicability of a package-only route.

    Package execution routes describe one installed implementation, not every
    object carrying the same broad role.  The route is necessary exactly when
    the admitted object's source denominator owns that implementation file.
    This is a mechanized refutation for other variants, never an optional or
    caller-selected waiver.
    """
    module = route_mechanism(route)
    if module is None:
        return False
    surfaces = declaration.get("surfaces")
    if type(surfaces) is not list or any(type(value) is not str for value in surfaces):
        raise ValueError("PACKAGE_EXECUTION_OBJECT_SURFACES_INVALID")
    return "file:" + module.IMPLEMENTATION in surfaces


def requires_route_assessment(
    declaration: dict[str, Any], route: dict[str, Any],
    *, selected_mechanisms: frozenset[str] = frozenset(),
) -> bool:
    """Keep derived roles visible until their implementation condition is resolved.

    A primary ``LEDGER`` declaration, for example, is not automatically the
    Verifier invocation ledger.  Conversely, a source-derived or consequential
    ``LEDGER`` role on another primary record cannot make the installed finite
    routes disappear merely by omitting their implementation file.  Such a
    derived role receives an assessment row; exact source adaptation may then
    prove the implementation-specific condition false, otherwise it remains
    ``UNKNOWN``.  This is conditional applicability, never an optional route.
    """
    module = route_mechanism(route)
    if module is None:
        return False
    primary = declaration.get("kind")
    if type(primary) is not str:
        raise ValueError("PACKAGE_EXECUTION_OBJECT_KIND_INVALID")
    # The caller has already established that ``route["object_kind"]`` is an
    # effective role of this object.  Every installed implementation-specific
    # route must therefore receive an assessment row.  Exact ownership makes
    # execution necessary; a reviewed source mismatch can explicitly refute
    # the implementation condition; ownership without a selection stays
    # UNKNOWN.  Omitting the row would create an empty behavioral denominator.
    return True


def validate_bindings(bindings: Any, rows: list[dict[str, Any]]) -> None:
    from verifier.runtime.package_instance_evidence import _require, _path, _HASH
    _require(type(bindings) is list and len(bindings) <= 4096, "PACKAGE_EXECUTION_SELECTION_COUNT")
    identifiers, seen = {row["object_id"] for row in rows}, set()
    registered = mechanisms()
    for binding in bindings:
        _require(type(binding) is dict and set(binding) == {"object_id", "mechanism", "reason", "evidence"},
                 "PACKAGE_EXECUTION_SELECTION_FIELDS")
        identifier = binding["object_id"]
        _require(type(identifier) is str and identifier in identifiers,
                 "PACKAGE_EXECUTION_OBJECT_INVALID")
        _require(type(binding["mechanism"]) is str and binding["mechanism"] in registered,
                 "PACKAGE_EXECUTION_MECHANISM_UNREGISTERED")
        key = identifier, binding["mechanism"]
        _require(key not in seen, "PACKAGE_EXECUTION_SELECTION_DUPLICATED")
        seen.add(key)
        _require(type(binding["reason"]) is str and len(binding["reason"]) <= 8192, "PACKAGE_EXECUTION_REASON_INVALID")
        refs = binding["evidence"]
        _require(type(refs) is list and len(refs) <= 256, "PACKAGE_EXECUTION_EVIDENCE_INVALID")
        for ref in refs:
            _require(type(ref) is dict and set(ref) == {"path", "sha256"} and type(ref["path"]) is str
                     and type(ref["sha256"]) is str and _HASH.fullmatch(ref["sha256"]) is not None,
                     "PACKAGE_EXECUTION_REFERENCE_INVALID")
            _path(ref["path"])


def _inside(path: Path, protected: Path) -> bool:
    return path == protected or path.is_relative_to(protected)


def _installed_source_checkout() -> Path | None:
    """Recognize this module's checkout only from its exact positive layout."""
    implementation = Path(__file__).resolve(strict=True)
    candidate = implementation.parents[3]
    expected = candidate / "src" / "verifier" / "runtime" / implementation.name
    try:
        if ((candidate / "objects.vstd").is_file()
                and expected.resolve(strict=True) == implementation):
            return candidate.resolve(strict=True)
    except OSError:
        pass
    return None


def _execution_source_root(snapshot: Any) -> Path:
    root = getattr(snapshot, "root", None)
    if root is not None:
        return Path(root).resolve(strict=True)
    checkout = _installed_source_checkout()
    if checkout is None:
        raise OSError("PACKAGE_EXECUTION_PRIVATE_TEMP_UNAVAILABLE")
    return checkout


def _temporary_parent_candidates(source_root: Path) -> tuple[Path, ...]:
    """Return verified external temp parents without inferring wheel layout."""
    root = source_root.resolve(strict=True)
    implementation = Path(__file__).resolve(strict=True)
    installed_package = implementation.parents[1]
    installed_source = _installed_source_checkout() or installed_package
    proposed = [Path(tempfile.gettempdir())]
    expected = root / "src" / "verifier" / "runtime" / implementation.name
    # Only a positive source-checkout binding authorizes the repository sibling
    # as a candidate. A wheel/site-packages depth is never guessed from parents.
    try:
        source_checkout = ((root / "objects.vstd").is_file()
            and expected.resolve(strict=True) == implementation)
    except OSError:
        source_checkout = False
    if source_checkout:
        proposed.append(root.parent)
    candidates, seen = [], set()
    for value in proposed:
        try:
            resolved = value.resolve(strict=True)
        except OSError:
            continue
        key = os.path.normcase(str(resolved))
        if (key not in seen and resolved.is_dir()
                and not _inside(resolved, root)
                and not _inside(resolved, installed_source)):
            seen.add(key)
            candidates.append(resolved)
    return tuple(candidates)


@contextmanager
def _private_temp_directory(source_root: Path) -> Iterator[Path]:
    """Create one private child filesystem on the greatest-capacity candidate."""
    implementation = Path(__file__).resolve(strict=True)
    protected = (source_root.resolve(strict=True),
        _installed_source_checkout() or implementation.parents[1])
    ranked = []
    for order, parent in enumerate(_temporary_parent_candidates(source_root)):
        try:
            ranked.append((shutil.disk_usage(parent).free, order, parent))
        except OSError:
            continue
    last_error: OSError | None = None
    for _, _, parent in sorted(ranked, key=lambda row: (-row[0], row[1])):
        temporary = None
        try:
            temporary = tempfile.TemporaryDirectory(prefix="vstd-package-execution-", dir=parent)
            directory = Path(temporary.name).resolve(strict=True)
            if directory.parent != parent or any(_inside(directory, value) for value in protected):
                raise OSError("private temporary directory escaped selected parent")
        except OSError as exc:
            last_error = exc
            if temporary is not None:
                try:
                    temporary.cleanup()
                except OSError:
                    pass
            continue
        try:
            yield directory
        except BaseException:
            # Cleanup is attempted, but cannot replace the primary worker,
            # launch or timeout error and never authorizes another launch.
            try:
                temporary.cleanup()
            except OSError:
                pass
            raise
        else:
            try:
                temporary.cleanup()
            except OSError as exc:
                raise OSError("PACKAGE_EXECUTION_PRIVATE_TEMP_CLEANUP_FAILED") from exc
        return
    raise OSError("PACKAGE_EXECUTION_PRIVATE_TEMP_UNAVAILABLE") from last_error


def _obligation(error: BaseException, status: str, reason: str) -> BaseException:
    """Attach the obligation result to an exception whose type and text stay protocol-visible."""
    error.vstd_obligation = (status, reason)  # type: ignore[attr-defined]
    return error


def _require_obligation(condition: bool, code: str, status: str, reason: str | None = None) -> None:
    """Raise ``code`` through the shared guard, classified at the obligation layer as ``status``."""
    from verifier.runtime.package_instance_evidence import _require
    try:
        _require(condition, code)
    except ValueError as exc:
        raise _obligation(exc, status, reason or code) from None


def _valid_source_pins(value: Any) -> bool:
    """Shape only: a JSON object from relative source path to one SHA-256 digest."""
    return type(value) is dict and all(
        type(path) is str and path != "" and type(digest) is str
        and _SOURCE_PIN_DIGEST.fullmatch(digest) is not None
        for path, digest in value.items())


def _pins_equal(value: Any, current: dict[str, str]) -> bool:
    """Shape-validate before equality; a malformed capture never matches the current tree."""
    return _valid_source_pins(value) and value == current


def _check_reply(report: Any, module: ModuleType, request: dict[str, Any], pins: dict[str, str]) -> None:
    """Classify a parsed child reply in the order its contradictions can be trusted.

    A missing or malformed echoed ``source_pins`` is unavailable evidence. A well-formed
    envelope whose binding differs is a semantic refusal. Pins that disagree with the
    stable tree are a child contradiction. The protocol transport keeps the historical
    ``PACKAGE_EXECUTION_SOURCE_CHANGED`` text for that contradiction; only the obligation
    reason is the stable-contradiction code.
    """
    from verifier.runtime.package_instance_evidence import _require
    _require(type(report) is dict, "PACKAGE_EXECUTION_REQUEST_BINDING_DIFFERS")
    # Reads stay type-safe even if a guard is disabled, so a broken guard fails closed.
    echoed = report.get("source_pins") if type(report) is dict else None
    _require_obligation(_valid_source_pins(echoed), "PACKAGE_EXECUTION_SOURCE_PINS_INVALID", "UNKNOWN")
    _require(set(report) == {"schema_version", "request", "source_pins", "observations"}
             and report.get("schema_version") == module.OBSERVATION_SCHEMA and report.get("request") == request,
             "PACKAGE_EXECUTION_REQUEST_BINDING_DIFFERS")
    _require_obligation(echoed == pins, "PACKAGE_EXECUTION_SOURCE_CHANGED", "FAIL",
                        "PACKAGE_EXECUTION_SOURCE_PINS_CONTRADICTED")


def _post_verdict_stable(snapshot: Any, key: tuple[str, str], executed: dict[str, Any]) -> None:
    """Any source change after the checker means no verdict is retained and no relaunch follows."""
    from verifier.runtime.local_ledger_worker import source_pins
    if not _pins_equal(executed.get("source_pins"), source_pins()):
        snapshot.executions.pop(key, None)
        raise _obligation(OSError("PACKAGE_EXECUTION_SOURCE_CHANGED"), "UNKNOWN", "PACKAGE_EXECUTION_SOURCE_CHANGED")


def _obligation_result(exc: BaseException, status: str) -> tuple[str, str]:
    """Closed obligation status and reason; raw Python text never becomes a reason."""
    attached = getattr(exc, _OBLIGATION_ATTRIBUTE, None)
    if attached is not None:
        return attached
    text = str(exc)
    if status == "UNKNOWN":
        return status, text if text.startswith("PACKAGE_") else "PACKAGE_EXECUTION_UNAVAILABLE"
    return status, text if _CLOSED_REASON.fullmatch(text) else "PACKAGE_EXECUTION_OBSERVATION_INVALID"


def execute_bound(snapshot: Any, item: NamespaceObject, selection: dict[str, Any]) -> dict[str, Any]:
    """Run one fixed worker after matching every executable source dependency."""
    from verifier.runtime.local_ledger_worker import source_pins
    module = mechanisms()[selection["mechanism"]]
    owned = set(snapshot.rows[item.object_id]["surfaces"])
    if not selection["reason"].strip() or not selection["evidence"]:
        raise OSError("PACKAGE_EXECUTION_SOURCE_REASON_UNAVAILABLE")
    if "file:" + module.IMPLEMENTATION not in owned or not any(ref["path"] == module.IMPLEMENTATION for ref in selection["evidence"]):
        raise OSError("PACKAGE_EXECUTION_OWNED_IMPLEMENTATION_UNAVAILABLE")
    for ref in selection["evidence"]:
        snapshot.read(ref)
    pins = source_pins()
    for relative, digest in pins.items():
        try:
            snapshot.read({"path": "src/verifier/" + relative, "sha256": digest})
        except ValueError as exc:
            # A digest that moved after capture is pin-capture drift, never instance-evidence
            # staleness (which stays a FAIL). Any other malformed pin is unavailable evidence.
            code = ("PACKAGE_EXECUTION_SOURCE_CHANGED"
                    if str(exc) == "PACKAGE_INSTANCE_EVIDENCE_DIGEST_DIFFERS"
                    else "PACKAGE_EXECUTION_SOURCE_PINS_INVALID")
            raise _obligation(OSError(code), "UNKNOWN", code) from None
        except OSError as exc:
            # Typed resource limits keep their own reason; an unreadable pin is drift.
            if str(exc).startswith("PACKAGE_"):
                raise
            raise _obligation(OSError("PACKAGE_EXECUTION_SOURCE_CHANGED"), "UNKNOWN",
                              "PACKAGE_EXECUTION_SOURCE_CHANGED") from None
    request = {"schema_version": module.REQUEST_SCHEMA, "nonce": os.urandom(32).hex(),
        "object_id": item.object_id, "object_digest": item.digest, "collection_digest": snapshot.collection_digest}
    environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "PATH") if key in os.environ}
    # Values are assigned only inside the private-directory lifetime.  The
    # parent process environment is never mutated, and all child temp variables
    # name the same bounded filesystem.
    environment.update(TEMP="", TMP="", TMPDIR="")
    submitted = canonical_bytes(request)
    command = [sys.executable, "-I", "-S", "-B", str(Path(__file__).with_name(module.WORKER))]
    timeout_seconds = _worker_timeout_seconds(module)
    parameters = {"input": submitted, "capture_output": True,
        "timeout": timeout_seconds, "check": False, "env": environment}
    record = observation.begin(request, selection, pins, command, parameters)
    # Capture on the parent boundary, never inside a worker-authored envelope.
    # A failed attempt is retained too; no exception authorizes an automatic retry.
    try:
        with _private_temp_directory(_execution_source_root(snapshot)) as private_temp:
            child_parameters = {**parameters, "env": {**environment,
                "TEMP": str(private_temp), "TMP": str(private_temp), "TMPDIR": str(private_temp)}}
            try:
                result = _run_package_worker(command, child_parameters, private_temp)
            except owned_process.OwnedProcessAbort as aborted:
                failed = aborted.result
                cause = aborted.cause
                record.update(
                    outcome=("CANCELLED" if isinstance(
                        cause, (KeyboardInterrupt, SystemExit, GeneratorExit)
                    ) else "OWNED_PROCESS_INTERNAL_ERROR"),
                    exception_type=type(cause).__name__,
                    returncode=None,
                    streams_complete=False,
                    stdout=observation.stream(failed.stdout, observation.OUTPUT_LIMIT),
                    stderr=observation.stream(failed.stderr, observation.STDERR_LIMIT),
                )
                raise cause.with_traceback(cause.__traceback__) from None

            record.update(
                outcome="REJECTED",
                returncode=result.returncode,
                streams_complete=(
                    result.streams_complete
                    and result.cleanup == owned_process.CLEANUP_CONFIRMED
                ),
                stdout=observation.stream(result.stdout, observation.OUTPUT_LIMIT),
                stderr=observation.stream(result.stderr, observation.STDERR_LIMIT),
            )
            if result.status == owned_process.STATUS_TIMEOUT:
                record.update(outcome="TIMEOUT", returncode=None, streams_complete=False)
                raise OSError("PACKAGE_EXECUTION_WORKER_TIMEOUT")
            if result.status == owned_process.STATUS_OUTPUT_CAP:
                record.update(outcome="OUTPUT_CAP_EXCEEDED", returncode=None,
                    streams_complete=False)
                raise OSError("PACKAGE_EXECUTION_OUTPUT_CAPACITY")
            if result.cleanup == owned_process.CLEANUP_NOT_CONFIRMED:
                record.update(outcome="CLEANUP_NOT_CONFIRMED", returncode=None,
                    streams_complete=False)
                raise OSError("PACKAGE_EXECUTION_CLEANUP_NOT_CONFIRMED")
            if result.cleanup == owned_process.CLEANUP_UNKNOWN:
                record.update(outcome="CLEANUP_UNKNOWN", returncode=None,
                    streams_complete=False)
                raise OSError("PACKAGE_EXECUTION_CLEANUP_UNKNOWN")
            if result.returncode is None:
                record.update(outcome="EXIT_STATUS_UNKNOWN", streams_complete=False)
                raise OSError("PACKAGE_EXECUTION_EXIT_STATUS_UNKNOWN")
            if result.returncode != 0:
                record["outcome"] = "NONZERO_EXIT"
                raise OSError("PACKAGE_EXECUTION_WORKER_UNAVAILABLE")
            try:
                report = strict_json_loads(result.stdout.decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise _obligation(exc, "UNKNOWN", "PACKAGE_EXECUTION_REPLY_ENCODING_INVALID") from None
            except ValueError as exc:
                raise _obligation(exc, "UNKNOWN", "PACKAGE_EXECUTION_REPLY_MALFORMED") from None
        # Recapture after the private filesystem has been cleaned. Cleanup is a
        # resource boundary, not part of the child's semantic PASS. A moved tree is
        # never a verdict, so it is decided before any contradiction in the reply.
        _require_obligation(source_pins() == pins, "PACKAGE_EXECUTION_SOURCE_CHANGED", "UNKNOWN")
        _check_reply(report, module, request, pins)
        record["outcome"] = "ACCEPTED"
        return report
    except subprocess.TimeoutExpired as exc:
        record.update(outcome="TIMEOUT", exception_type=type(exc).__name__,
            stdout=observation.stream(exc.stdout, observation.OUTPUT_LIMIT),
            stderr=observation.stream(exc.stderr, observation.STDERR_LIMIT))
        raise
    except Exception as exc:
        record["exception_type"] = type(exc).__name__
        if record["outcome"] == "LAUNCH_ATTEMPTED":
            record["outcome"] = "LAUNCH_ERROR"
        raise
    finally:
        snapshot.execution_transports[(item.object_id, module.ADAPTER)] = observation.seal(record)


def evaluate(snapshot: Any, item: NamespaceObject, route: dict[str, Any]) -> dict[str, Any] | None:
    module = route_mechanism(route)
    if module is None:
        return None
    selection = snapshot.execution_checks.get((item.object_id, module.ADAPTER))
    if selection is None or selection["mechanism"] != module.ADAPTER:
        # A different selected implementation is not an applicability refutation.
        return None
    return module.evaluate(snapshot, item, route)


def _current_source_pins() -> dict[str, str]:
    from verifier.runtime.local_ledger_worker import source_pins
    return source_pins()


def _still_equal(value: Any, expected: bytes | None) -> bool:
    """Whether ``value`` still has its precheck canonical bytes; unserializable means changed."""
    try:
        return canonical_bytes(value) == expected
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
        return False


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _code_constant(value: Any) -> list[Any]:
    """Return a closed structural form without marshal reference aliases."""

    if value is None:
        return ["none"]
    if value is Ellipsis:
        return ["ellipsis"]
    if type(value) is bool:
        return ["bool", value]
    if type(value) is int:
        return ["int", str(value)]
    if type(value) is float:
        return ["float", value.hex()]
    if type(value) is complex:
        return ["complex", value.real.hex(), value.imag.hex()]
    if type(value) is str:
        return ["str", value]
    if type(value) is bytes:
        return ["bytes", value.hex()]
    if type(value) is tuple:
        return ["tuple", [_code_constant(item) for item in value]]
    if type(value) is frozenset:
        items = [_code_constant(item) for item in value]
        items.sort(key=canonical_bytes)
        return ["frozenset", items]
    if type(value) is CodeType:
        return ["code", _code_record(value)]
    raise TypeError("unsupported checker code constant")


def _code_record(code: CodeType) -> dict[str, Any]:
    """Describe every Python 3.12 code field relevant to execution and tracing."""

    return {
        "argcount": code.co_argcount,
        "cellvars": list(code.co_cellvars),
        "code": code.co_code.hex(),
        "consts": [_code_constant(item) for item in code.co_consts],
        "exceptiontable": code.co_exceptiontable.hex(),
        "filename": code.co_filename,
        "firstlineno": code.co_firstlineno,
        "flags": code.co_flags,
        "freevars": list(code.co_freevars),
        "kwonlyargcount": code.co_kwonlyargcount,
        "linetable": code.co_linetable.hex(),
        "name": code.co_name,
        "names": list(code.co_names),
        "nlocals": code.co_nlocals,
        "posonlyargcount": code.co_posonlyargcount,
        "qualname": code.co_qualname,
        "stacksize": code.co_stacksize,
        "varnames": list(code.co_varnames),
    }


def _code_digest(value: Any) -> str:
    """Bind the loaded parent callable without executing it in the trust boundary."""

    code = getattr(value, "__code__", None)
    if type(code) is not CodeType:
        raise OSError("PACKAGE_EXECUTION_CHECKER_LOADED_CODE_UNAVAILABLE")
    try:
        return _sha256(canonical_bytes(_code_record(code)))
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
        raise OSError("PACKAGE_EXECUTION_CHECKER_LOADED_CODE_UNAVAILABLE") from None


def _detached_json(value: Any) -> Any:
    """Return a canonical JSON copy so report mutation cannot rewrite retained evidence."""

    return strict_json_loads(canonical_bytes(value).decode("utf-8"))


def _checker_source(module: ModuleType) -> tuple[Path, Path, str]:
    """Resolve one installed checker below this distribution's fixed source root."""

    source_root = Path(__file__).resolve(strict=True).parents[2]
    raw_path = getattr(module, "__file__", None)
    if type(raw_path) is not str:
        raise OSError("PACKAGE_EXECUTION_CHECKER_SOURCE_UNAVAILABLE")
    path = Path(raw_path).resolve(strict=True)
    try:
        relative = path.relative_to(source_root).as_posix()
    except ValueError:
        raise OSError("PACKAGE_EXECUTION_CHECKER_SOURCE_OUTSIDE_PACKAGE") from None
    if path.suffix != ".py" or not relative.startswith("verifier/runtime/"):
        raise OSError("PACKAGE_EXECUTION_CHECKER_SOURCE_INVALID")
    return source_root, path, relative


def _checker_unknown(code: str) -> OSError:
    return OSError(code)


def _accepted_checker_receipt(
    module: ModuleType,
    coordinate: str,
    executed: dict[str, Any],
) -> dict[str, Any]:
    """Execute and validate one source-bound checker receipt.

    The worker is copied into the private directory before launch, so the child
    executes the exact bytes hashed here. The checker module itself is supplied
    as a source-relative coordinate; the child compiles the bytes it hashed
    rather than consulting bytecode or the parent's imported module cache.
    """

    adapter = getattr(module, "ADAPTER", None)
    if type(adapter) is not str or not adapter:
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_ADAPTER_INVALID")
    contract = "request-bound" if adapter in REQUEST_BOUND_ADAPTERS else "observations-only"
    request = executed.get("request") if contract == "request-bound" else None
    if contract == "request-bound" and type(request) is not dict:
        raise _checker_unknown("PACKAGE_EXECUTION_REQUEST_ABSENT")
    source_root, checker_path, checker_relative = _checker_source(module)
    try:
        checker_before = checker_path.read_bytes()
        worker_path = Path(__file__).with_name("package_checker_worker.py").resolve(strict=True)
        worker_bytes = worker_path.read_bytes()
    except OSError:
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_SOURCE_UNAVAILABLE") from None
    checker_digest = _sha256(checker_before)
    worker_digest = _sha256(worker_bytes)
    loaded_code_digest = _code_digest(getattr(module, "check_observations", None))
    loaded_contract = getattr(module, "CHECKER_CONTRACT", None)
    if loaded_contract is not None and type(loaded_contract) is not str:
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_LOADED_CONTRACT_INVALID")
    payload = {
        "schema_version": "verifier-package-checker-request-1",
        "adapter": adapter,
        "coordinate": coordinate,
        "contract": contract,
        "checker_relative": checker_relative,
        "checker_sha256": checker_digest,
        "loaded_checker_code_sha256": loaded_code_digest,
        "loaded_checker_contract": loaded_contract,
        "observations": _detached_json(executed.get("observations")),
        "request": _detached_json(request) if request is not None else None,
    }
    submitted = canonical_bytes(payload)
    request_digest = value_digest(payload)
    environment = {
        key: os.environ[key]
        for key in ("SYSTEMROOT", "WINDIR", "PATH")
        if key in os.environ
    }
    try:
        with tempfile.TemporaryDirectory(prefix="vstd-package-checker-") as folder:
            private_temp = Path(folder).resolve(strict=True)
            copied_worker = private_temp / "package_checker_worker.py"
            copied_worker.write_bytes(worker_bytes)
            environment.update(
                TEMP=str(private_temp), TMP=str(private_temp), TMPDIR=str(private_temp)
            )
            parameters = {
                "input": submitted,
                "timeout": _CHECKER_TIMEOUT_SECONDS,
                "env": environment,
            }
            command = [
                sys.executable,
                *(["-O"] * sys.flags.optimize),
                "-I",
                "-S",
                "-B",
                str(copied_worker),
                str(source_root),
            ]
            result = _run_package_checker(command, parameters, private_temp)
    except owned_process.OwnedProcessAbort as exc:
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_INTERNAL_ERROR") from exc
    except (OSError, ValueError):
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_LAUNCH_UNAVAILABLE") from None
    # Accept one process observation by positive construction.  Deny-listing known
    # bad enum values would let a new/forged status, cleanup state or incomplete
    # stream become semantic evidence.  Exact types also keep ``False`` distinct
    # from the integer exit status zero.
    try:
        status = result.status
        cleanup = result.cleanup
        returncode = result.returncode
        stdout = result.stdout
        stderr = result.stderr
        stdout_overflowed = result.stdout_overflowed
        stderr_overflowed = result.stderr_overflowed
        streams_complete = result.streams_complete
    except Exception:
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_PROCESS_RESULT_INVALID") from None
    if (
        type(stdout) is not bytes
        or type(stderr) is not bytes
        or type(stdout_overflowed) is not bool
        or type(stderr_overflowed) is not bool
        or type(streams_complete) is not bool
    ):
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_STREAM_INVALID")
    if type(status) is not str:
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_STATUS_UNKNOWN")
    if type(cleanup) is not str:
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_CLEANUP_UNKNOWN")
    if status == owned_process.STATUS_TIMEOUT:
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_TIMEOUT")
    if (
        status == owned_process.STATUS_OUTPUT_CAP
        or stdout_overflowed
        or stderr_overflowed
    ):
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_OUTPUT_CAPACITY")
    if status != owned_process.STATUS_EXITED:
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_STATUS_UNKNOWN")
    if cleanup == owned_process.CLEANUP_NOT_CONFIRMED:
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_CLEANUP_NOT_CONFIRMED")
    if cleanup == owned_process.CLEANUP_UNKNOWN:
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_CLEANUP_UNKNOWN")
    if cleanup != owned_process.CLEANUP_CONFIRMED:
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_CLEANUP_UNKNOWN")
    if streams_complete is not True:
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_STREAM_INCOMPLETE")
    if type(returncode) is not int:
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_EXIT_STATUS_UNKNOWN")
    if returncode != 0:
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_UNAVAILABLE")
    try:
        parsed = strict_json_loads(stdout.decode("utf-8"))
        receipt = _detached_json(parsed)
        checker_after = checker_path.read_bytes()
        worker_after = worker_path.read_bytes()
    except (OSError, UnicodeError, ValueError, TypeError, OverflowError, RecursionError):
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_RECEIPT_INVALID") from None
    fields = {
        "schema_version",
        "request_digest",
        "adapter",
        "coordinate",
        "contract",
        "checker_relative",
        "checker_sha256_before",
        "checker_sha256_after",
        "loaded_checker_code_sha256",
        "loaded_checker_contract",
        "worker_sha256_before",
        "worker_sha256_after",
        "status",
        "reason",
        "verdict",
    }
    if type(receipt) is not dict or set(receipt) != fields:
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_RECEIPT_INVALID")
    current_checker_digest = _sha256(checker_after)
    current_worker_digest = _sha256(worker_after)
    expected = {
        "schema_version": _CHECKER_SCHEMA,
        "request_digest": request_digest,
        "adapter": adapter,
        "coordinate": coordinate,
        "contract": contract,
        "checker_relative": checker_relative,
        "checker_sha256_before": checker_digest,
        "checker_sha256_after": current_checker_digest,
        "loaded_checker_code_sha256": loaded_code_digest,
        "loaded_checker_contract": loaded_contract,
        "worker_sha256_before": worker_digest,
        "worker_sha256_after": current_worker_digest,
    }
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_INTEGRITY_UNCERTAIN")
    if checker_digest != current_checker_digest or worker_digest != current_worker_digest:
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_SOURCE_CHANGED")
    if receipt["status"] == "PASS":
        if receipt["verdict"] is not True or receipt["reason"] != "PACKAGE_EXECUTION_CHECKER_ACCEPTED":
            raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_RECEIPT_INVALID")
    elif receipt["status"] == "FAIL":
        if receipt["verdict"] is not False or receipt["reason"] != "PACKAGE_EXECUTION_OBSERVATION_REFUTED":
            raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_RECEIPT_INVALID")
    elif receipt["status"] == "UNKNOWN":
        if receipt["verdict"] is not None or not (
            type(receipt["reason"]) is str
            and receipt["reason"].startswith("PACKAGE_EXECUTION_CHECKER_")
        ):
            raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_RECEIPT_INVALID")
    else:
        raise _checker_unknown("PACKAGE_EXECUTION_CHECKER_RECEIPT_INVALID")
    return receipt


def check_executed(module: ModuleType, coordinate: str, executed: dict[str, Any]) -> bool:
    """Run one checker from current source in a fresh isolated interpreter.

    The accepted exchange is serialized before launch and checked again after it.
    Imported parent modules, stale bytecode and returned aliases therefore cannot
    supply a verdict. A checker defect or any source/process-integrity uncertainty
    raises an availability error; only exact source-bound ``False`` is semantic FAIL.
    """

    record_bytes = canonical_bytes(executed)
    receipt = _accepted_checker_receipt(module, coordinate, executed)
    if not _still_equal(executed, record_bytes):
        raise _checker_unknown("PACKAGE_EXECUTION_RECORD_MUTATED")
    if receipt["status"] == "PASS":
        return True
    if receipt["status"] == "FAIL":
        return False
    raise _checker_unknown(receipt["reason"])


def evaluate_selected(snapshot: Any, item: NamespaceObject, route: dict[str, Any]) -> dict[str, Any] | None:
    """Share one object's one mechanism, never evidence from a different role."""
    module = route_mechanism(route)
    if module is None:
        return None
    key = item.object_id, module.ADAPTER
    selection = snapshot.execution_checks.get(key)
    if selection is None or selection["mechanism"] != module.ADAPTER:
        return None
    result: dict[str, Any] = {"status": "UNKNOWN", "evidence_origin": "SOURCE_BOUND_FRESH_EXECUTION",
        "object_id": item.object_id, "object_digest": item.digest,
        "collection_digest": snapshot.collection_digest,
        "coordinate": route["coordinate"], "obligation_id": route["obligation_id"],
        "semantic_version": route["semantic_version"],
        "proposition_digest": route["proposition_digest"],
        "checking_mechanism": route["checking_mechanism"],
        "selection_digest": value_digest(selection), "selection": _detached_json(selection), "replay": None,
        "parent_observation_digest": None,
        "reason": "Fresh execution has not been established.", "applicability_established": False}
    transport = getattr(snapshot, "execution_transports", {})
    if key in transport:
        result["parent_observation_digest"] = transport[key]["observation_digest"]
    if key in snapshot.execution_failures:
        return {**result, **snapshot.execution_failures[key]}
    try:
        cached = key in snapshot.executions
        if not cached:
            snapshot.executions[key] = module._execute(snapshot, item, selection)
        executed = snapshot.executions[key]
        # Cache membership is not evidence.  Rebind every retained exchange to
        # the current object, collection and selection before any domain oracle
        # can observe it; this rejects same-kind cross-object transplantation.
        observation.verify_accepted(
            transport.get(key), executed, selection=selection, item=item,
            collection_digest=snapshot.collection_digest, module=module,
        )
        if cached and not _pins_equal(executed.get("source_pins"), _current_source_pins()):
            # A cached receipt bound to earlier source bytes is not current execution.
            # Discard it and launch once more through the same bounded path, so the
            # old bytes are never blessed. A fresh launch is checked against the
            # current pins by execute_bound itself.
            del snapshot.executions[key]
            snapshot.executions[key] = module._execute(snapshot, item, selection)
            executed = snapshot.executions[key]
            observation.verify_accepted(
                transport.get(key), executed, selection=selection, item=item,
                collection_digest=snapshot.collection_digest, module=module,
            )
        passed = check_executed(module, route["coordinate"], executed)
        # The checker runs on copies, but a checker with access to the snapshot could
        # still replace the retained exchange. Re-verify it so no verdict outlives a change.
        observation.verify_accepted(
            transport.get(key), executed, selection=selection, item=item,
            collection_digest=snapshot.collection_digest, module=module,
        )
        # A source change after the verdict, however the verdict was reached, retains no PASS.
        _post_verdict_stable(snapshot, key, executed)
        result.update(status="PASS" if passed else "FAIL", replay=_detached_json(executed),
            reason=module.BOUNDARY if passed else "PACKAGE_EXECUTION_OBSERVATION_REFUTED",
            applicability_established=True,
            applicability_reason="The exact owned installed implementation is selected for this finite execution proposition. " + route["reason"])
    except (OSError, ImportError, MemoryError, RecursionError, subprocess.TimeoutExpired) as exc:
        result["status"], result["reason"] = _obligation_result(exc, "UNKNOWN")
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError) as exc:
        result["status"], result["reason"] = _obligation_result(exc, "FAIL")
    if key in transport:
        result["parent_observation_digest"] = transport[key]["observation_digest"]
    if key not in snapshot.executions:
        snapshot.execution_failures[key] = {field: result[field] for field in ("status", "reason")}
    return result
