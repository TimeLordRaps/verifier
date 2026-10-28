"""Fresh source-bound package checker worker for Verifier Standard (VSTD).

The parent supplies JavaScript Object Notation (JSON) observations, never a
module name or command. This worker compiles the exact checker bytes it hashes,
uses no cached bytecode, and emits a bounded Secure Hash Algorithm 256-bit
(SHA-256) receipt. A checker exception or integrity uncertainty is UNKNOWN;
only an exact Boolean false is a semantic refutation.
"""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import inspect
import json
from pathlib import Path
import sys
import tempfile
from types import CodeType, ModuleType
from typing import Any


_REQUEST_SCHEMA = "verifier-package-checker-request-1"
_RECEIPT_SCHEMA = "verifier-package-checker-receipt-1"
_REQUEST_BOUND_ADAPTERS = frozenset({"verifier-emulated-control-1"})
_PARAMETERS = {
    "observations-only": ("coordinate", "observed"),
    "request-bound": ("coordinate", "observed", "request"),
}
_REQUEST_LIMIT = 2 * 1024 * 1024
_DIAGNOSTIC_LIMIT = 65536


class _BoundedTextSink:
    """Discard checker diagnostics after enforcing a finite character bound."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.count = 0

    def write(self, value: str) -> int:
        if type(value) is not str:
            raise TypeError("text output required")
        self.count += len(value)
        if self.count > self.limit:
            raise OSError("checker diagnostic capacity exceeded")
        return len(value)

    def flush(self) -> None:
        return None


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _value_digest(value: Any) -> str:
    return _sha256(_canonical(value))


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
        items.sort(key=_canonical)
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
    code = getattr(value, "__code__", None)
    if type(code) is not CodeType:
        raise ValueError("PACKAGE_EXECUTION_CHECKER_LOADED_CODE_UNAVAILABLE")
    return _sha256(_canonical(_code_record(code)))


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON member")
        value[key] = item
    return value


def _loads(raw: bytes) -> Any:
    return json.loads(
        raw,
        object_pairs_hook=_pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError("nonportable JSON number: " + value)
        ),
    )


def _safe_checker_path(source_root: Path, relative: Any) -> Path:
    if type(relative) is not str or not relative.startswith("verifier/runtime/"):
        raise ValueError("checker source coordinate invalid")
    candidate = (source_root / Path(*relative.split("/"))).resolve(strict=True)
    if (
        candidate.suffix != ".py"
        or not candidate.is_relative_to(source_root)
        or candidate.parent != source_root / "verifier" / "runtime"
    ):
        raise ValueError("checker source coordinate invalid")
    return candidate


def _load_held_checker(path: Path, raw: bytes) -> ModuleType:
    """Compile the held source bytes without consulting a bytecode cache."""

    name = "verifier.runtime." + path.stem
    module = ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = "verifier.runtime"
    sys.modules[name] = module
    # Compile only the held bytes.  Inheriting this worker's future flags would
    # change a checker that did not declare those flags in its own source.
    code = compile(
        raw,
        str(path),
        "exec",
        dont_inherit=True,
        optimize=sys.flags.optimize,
    )
    exec(code, module.__dict__)
    return module


def _contract(module: ModuleType, adapter: str) -> str:
    expected = "request-bound" if adapter in _REQUEST_BOUND_ADAPTERS else "observations-only"
    declared = getattr(module, "CHECKER_CONTRACT", None)
    if declared is None:
        if expected == "request-bound":
            raise ValueError("PACKAGE_EXECUTION_CHECKER_CONTRACT_OMITTED")
    elif declared != expected:
        raise ValueError("PACKAGE_EXECUTION_CHECKER_CONTRACT_DRIFT")
    checker = getattr(module, "check_observations", None)
    try:
        parameters = tuple(inspect.signature(checker).parameters.values())
    except (TypeError, ValueError):
        raise ValueError("PACKAGE_EXECUTION_CHECKER_CONTRACT_DRIFT") from None
    shape = tuple((parameter.name, parameter.kind) for parameter in parameters)
    required = tuple(
        (name, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        for name in _PARAMETERS[expected]
    )
    if shape != required:
        raise ValueError("PACKAGE_EXECUTION_CHECKER_CONTRACT_DRIFT")
    return expected


def _receipt_base(
    payload: dict[str, Any], worker_before: str, checker_before: str
) -> dict[str, Any]:
    return {
        "schema_version": _RECEIPT_SCHEMA,
        "request_digest": _value_digest(payload),
        "adapter": payload["adapter"],
        "coordinate": payload["coordinate"],
        "contract": payload["contract"],
        "checker_relative": payload["checker_relative"],
        "checker_sha256_before": checker_before,
        "checker_sha256_after": checker_before,
        "loaded_checker_code_sha256": "sha256:" + "0" * 64,
        "loaded_checker_contract": None,
        "worker_sha256_before": worker_before,
        "worker_sha256_after": worker_before,
        "status": "UNKNOWN",
        "reason": "PACKAGE_EXECUTION_CHECKER_UNAVAILABLE",
        "verdict": None,
    }


def _validate_payload(value: Any) -> dict[str, Any]:
    fields = {
        "schema_version",
        "adapter",
        "coordinate",
        "contract",
        "checker_relative",
        "checker_sha256",
        "loaded_checker_code_sha256",
        "loaded_checker_contract",
        "observations",
        "request",
    }
    if type(value) is not dict or set(value) != fields:
        raise ValueError("closed checker request required")
    if (
        value["schema_version"] != _REQUEST_SCHEMA
        or type(value["adapter"]) is not str
        or not value["adapter"]
        or type(value["coordinate"]) is not str
        or not value["coordinate"]
        or value["contract"] not in _PARAMETERS
        or type(value["checker_sha256"]) is not str
        or type(value["loaded_checker_code_sha256"]) is not str
        or value["loaded_checker_contract"] is not None
        and type(value["loaded_checker_contract"]) is not str
    ):
        raise ValueError("closed checker request required")
    return value


def main() -> int:
    raw = sys.stdin.buffer.read(_REQUEST_LIMIT + 1)
    if len(raw) > _REQUEST_LIMIT or len(sys.argv) != 2:
        raise ValueError("bounded checker request required")
    payload = _validate_payload(_loads(raw))
    source_root = Path(sys.argv[1]).resolve(strict=True)
    if not (source_root / "verifier" / "__init__.py").is_file():
        raise ValueError("package source root unavailable")
    checker_path = _safe_checker_path(source_root, payload["checker_relative"])
    worker_path = Path(__file__).resolve(strict=True)
    worker_bytes = worker_path.read_bytes()
    checker_bytes = checker_path.read_bytes()
    worker_before = _sha256(worker_bytes)
    checker_before = _sha256(checker_bytes)
    receipt = _receipt_base(payload, worker_before, checker_before)
    try:
        if checker_before != payload["checker_sha256"]:
            raise ValueError("PACKAGE_EXECUTION_CHECKER_SOURCE_CHANGED")
        with tempfile.TemporaryDirectory(prefix="vstd-checker-import-") as folder:
            sys.pycache_prefix = str(Path(folder) / "empty-bytecode")
            sys.path.insert(0, str(source_root))
            module = _load_held_checker(checker_path, checker_bytes)
            if getattr(module, "ADAPTER", None) != payload["adapter"]:
                raise ValueError("PACKAGE_EXECUTION_CHECKER_ADAPTER_INVALID")
            contract = _contract(module, payload["adapter"])
            receipt["loaded_checker_contract"] = getattr(
                module, "CHECKER_CONTRACT", None
            )
            if receipt["loaded_checker_contract"] != payload["loaded_checker_contract"]:
                raise ValueError("PACKAGE_EXECUTION_CHECKER_LOADED_CONTRACT_DIFFERS")
            if contract != payload["contract"]:
                raise ValueError("PACKAGE_EXECUTION_CHECKER_CONTRACT_DRIFT")
            checker = module.check_observations
            receipt["loaded_checker_code_sha256"] = _code_digest(checker)
            if (
                receipt["loaded_checker_code_sha256"]
                != payload["loaded_checker_code_sha256"]
            ):
                raise ValueError("PACKAGE_EXECUTION_CHECKER_LOADED_CODE_DIFFERS")
            observed = payload["observations"]
            request = payload["request"]
            observed_before = _canonical(observed)
            request_before = None if request is None else _canonical(request)
            sink = _BoundedTextSink(_DIAGNOSTIC_LIMIT)
            with redirect_stdout(sink), redirect_stderr(sink):
                verdict = (
                    checker(payload["coordinate"], observed)
                    if contract == "observations-only"
                    else checker(payload["coordinate"], observed, request=request)
                )
            if _canonical(observed) != observed_before or (
                request is not None and _canonical(request) != request_before
            ):
                raise ValueError("PACKAGE_EXECUTION_CHECKER_VIEW_MUTATED")
            if verdict is True:
                receipt.update(
                    status="PASS",
                    reason="PACKAGE_EXECUTION_CHECKER_ACCEPTED",
                    verdict=True,
                )
            elif verdict is False:
                receipt.update(
                    status="FAIL",
                    reason="PACKAGE_EXECUTION_OBSERVATION_REFUTED",
                    verdict=False,
                )
            else:
                raise ValueError("PACKAGE_EXECUTION_CHECKER_RESULT_INVALID")
    except BaseException as exc:
        code = str(exc)
        receipt.update(
            status="UNKNOWN",
            reason=(
                code
                if type(code) is str and code.startswith("PACKAGE_EXECUTION_CHECKER_")
                else "PACKAGE_EXECUTION_CHECKER_RAISED"
            ),
            verdict=None,
        )
    checker_after = _sha256(checker_path.read_bytes())
    worker_after = _sha256(worker_path.read_bytes())
    receipt["checker_sha256_after"] = checker_after
    receipt["worker_sha256_after"] = worker_after
    if checker_after != checker_before or worker_after != worker_before:
        receipt.update(
            status="UNKNOWN",
            reason="PACKAGE_EXECUTION_CHECKER_SOURCE_CHANGED",
            verdict=None,
        )
    sys.stdout.buffer.write(_canonical(receipt) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
