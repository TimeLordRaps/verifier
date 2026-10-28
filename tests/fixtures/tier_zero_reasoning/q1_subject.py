"""Subjects for independent Q1 test and audit-hook witnesses."""
from __future__ import annotations

import os
from pathlib import Path


def subject(value: int) -> int:
    return value + 1


def write_text(path: str) -> None:
    Path(path).write_text("observed", encoding="utf-8", newline="")


def c_write(file_descriptor: int) -> None:
    os.write(file_descriptor, b"c-write")
