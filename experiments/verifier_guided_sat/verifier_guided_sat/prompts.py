"""Render frozen generic prompts without held-out-domain tuning."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_prompts(experiment_root: Path) -> tuple[str, str, str]:
    prompt_root = experiment_root / "prompts"
    return (
        (prompt_root / "system.txt").read_text(encoding="utf-8"),
        (prompt_root / "arm_b.txt").read_text(encoding="utf-8"),
        (prompt_root / "arm_c.txt").read_text(encoding="utf-8"),
    )


def render_user_prompt(
    template: str, *, instance: dict[str, Any], contract: dict[str, Any]
) -> str:
    return template.replace("{{INSTANCE}}", _pretty(instance)).replace(
        "{{VERIFIER_CONTRACT}}", _pretty(contract)
    )


def _pretty(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True)
