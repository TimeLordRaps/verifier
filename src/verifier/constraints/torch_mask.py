"""Portable PyTorch application of an engine-produced packed token mask."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any


def _allowed_vector(packed_mask: bytes, vocabulary_size: int, *, device: Any) -> Any:
    try:
        import torch
    except ImportError as exc:  # pragma: no cover - exercised only without the optional extra
        raise RuntimeError("PyTorch is required; install verifier-standard[torch]") from exc

    expected_bytes = (vocabulary_size + 7) // 8
    if len(packed_mask) < expected_bytes:
        raise ValueError(
            f"packed mask has {len(packed_mask)} bytes but vocabulary size {vocabulary_size} requires {expected_bytes}"
        )
    packed = torch.tensor(list(packed_mask[:expected_bytes]), dtype=torch.uint8, device=device)
    token_ids = torch.arange(vocabulary_size, dtype=torch.long, device=device)
    return ((packed[token_ids // 8] >> (token_ids % 8)) & 1).bool()


def apply_packed_token_mask_inplace(logits: Any, packed_masks: bytes | Sequence[bytes]) -> tuple[int, ...]:
    """Set disallowed logits to ``-inf`` and return allowed counts per row.

    The implementation intentionally uses ordinary eager PyTorch operations.  It
    does not invoke ``torch.compile`` or a platform compiler, which keeps the seam
    usable on Windows installations that lack an OpenMP C++ toolchain.
    """

    try:
        import torch
    except ImportError as exc:  # pragma: no cover - exercised only without the optional extra
        raise RuntimeError("PyTorch is required; install verifier-standard[torch]") from exc

    if not isinstance(logits, torch.Tensor):
        raise TypeError("logits must be a torch.Tensor")
    if not logits.is_floating_point():
        raise TypeError("logits must use a floating-point dtype")
    if logits.ndim not in (1, 2):
        raise ValueError("logits must have shape [vocabulary] or [batch, vocabulary]")

    rows = logits.unsqueeze(0) if logits.ndim == 1 else logits
    masks = [packed_masks] if isinstance(packed_masks, bytes) else list(packed_masks)
    if len(masks) != rows.shape[0]:
        raise ValueError(f"received {len(masks)} masks for logits batch size {rows.shape[0]}")

    allowed_counts: list[int] = []
    for row_index, packed_mask in enumerate(masks):
        if not isinstance(packed_mask, bytes):
            raise TypeError("each packed mask must be bytes")
        allowed = _allowed_vector(packed_mask, rows.shape[1], device=rows.device)
        rows[row_index].masked_fill_(~allowed, float("-inf"))
        allowed_counts.append(int(allowed.sum().item()))
    return tuple(allowed_counts)
