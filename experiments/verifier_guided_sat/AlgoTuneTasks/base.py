"""Constructor-compatible base for the three exact retained AlgoTune tasks.

The upstream task files depend only on ``Task`` construction and the registration
decorator.  This local, source-visible shim deliberately provides nothing else.
"""
from __future__ import annotations

from typing import Any, Callable, TypeVar


_TaskType = TypeVar("_TaskType")


class Task:
    """Accept upstream constructor options without adding hidden behavior."""

    def __init__(self, **_: Any) -> None:
        pass


def register_task(_: str) -> Callable[[_TaskType], _TaskType]:
    """Retain the decorated class unchanged; no global registry is constructed."""

    def decorator(task_class: _TaskType) -> _TaskType:
        return task_class

    return decorator
