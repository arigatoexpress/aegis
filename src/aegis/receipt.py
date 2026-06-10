"""Canonical JSON + tamper-evident receipt hashing.

``canonical_json`` + ``receipt_hash`` is the identical primitive that appeared in
5+ files across the three source repos. Order-independent, side-effect-free,
sha256. No '0x'/'sha256:' prefix baked in (configurable).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

__all__ = ["canonical_json", "receipt_hash", "derive_nonce"]


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, compact separators, str fallback."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def receipt_hash(obj: Any, *, prefix: str = "") -> str:
    """sha256 over the canonical JSON of ``obj``. Stable across runs/hosts."""
    digest = hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()
    return f"{prefix}{digest}" if prefix else digest


def derive_nonce(*parts: Any, length: int = 16) -> str:
    """Deterministic short idempotency key from arbitrary parts."""
    digest = hashlib.sha256(canonical_json(list(parts)).encode("utf-8")).hexdigest()
    return digest[: max(1, length)]
