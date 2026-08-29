"""Shared internal coordinates for the Verifier Standard (VSTD) generic-run profile."""

from __future__ import annotations

from enum import Enum


RUN_SCHEMA_VERSION = "VSTD-1"
RUN_RECEIPT_KIND = "generic_computational_run"


class RunError(RuntimeError):
    """Manifest, capture, or impact error that must fail closed."""


class RunOutcome(str, Enum):
    COMPLETED = "COMPLETED"
    NONZERO_EXIT = "NONZERO_EXIT"
    MISSING_INPUT = "MISSING_INPUT"
    MISSING_OUTPUT = "MISSING_OUTPUT"
    TIMEOUT = "TIMEOUT"
    EXCEPTION = "EXCEPTION"


class DeterminismDeclaration(str, Enum):
    DETERMINISTIC = "DETERMINISTIC"
    NONDETERMINISTIC = "NONDETERMINISTIC"
    UNKNOWN = "UNKNOWN"
