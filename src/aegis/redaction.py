"""Redaction helpers: key-name redaction + span scrubbing.

Pure. Used both before persisting receipts (so secrets never hit the audit log)
and for output hygiene (scrub flagged spans from model output / tool results).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

__all__ = ["DEFAULT_SECRET_KEYS", "redact_mapping", "apply_spans", "redact_text"]

# KEY names whose VALUE should be scrubbed when present. Configurable per Guard.
DEFAULT_SECRET_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "authorization",
        "auth",
        "private_key",
        "client_secret",
        "session",
        "cookie",
        "credential",
        "credentials",
    }
)

_MASK = "[REDACTED]"


def _key_is_secret(key: str, markers: Iterable[str]) -> bool:
    low = key.lower()
    return any(m in low for m in markers)


def redact_mapping(obj: Any, markers: Iterable[str] = DEFAULT_SECRET_KEYS) -> Any:
    """Recursively replace a VALUE whenever its KEY matches a secret marker.

    Returns a new structure; never mutates the input.
    """
    marker_set = tuple(markers)
    if isinstance(obj, Mapping):
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            if isinstance(k, str) and _key_is_secret(k, marker_set):
                out[k] = _MASK
            else:
                out[k] = redact_mapping(v, marker_set)
        return out
    if isinstance(obj, list):
        return [redact_mapping(v, marker_set) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact_mapping(v, marker_set) for v in obj)
    return obj


def apply_spans(text: str, spans: Iterable[tuple[int, int]], *, keep: int = 4) -> str:
    """Scrub matched ``[start, end)`` spans from text, head...tail style.

    Overlapping/unsorted spans are merged. Each scrubbed span keeps up to
    ``keep`` leading chars then masks the rest, so receipts stay legible without
    leaking the secret body.
    """
    norm = sorted(
        (max(0, int(s)), min(len(text), int(e))) for s, e in spans if int(e) > int(s)
    )
    if not norm:
        return text
    merged: list[list[int]] = []
    for s, e in norm:
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])

    out: list[str] = []
    cursor = 0
    for s, e in merged:
        out.append(text[cursor:s])
        chunk = text[s:e]
        head = chunk[:keep]
        out.append(f"{head}{_MASK}" if head else _MASK)
        cursor = e
    out.append(text[cursor:])
    return "".join(out)


def redact_text(text: str, fragments: Iterable[str]) -> str:
    """Replace each literal fragment occurrence in text with a mask."""
    for frag in fragments:
        if frag:
            text = text.replace(frag, _MASK)
    return text
