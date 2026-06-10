"""Store + Clock protocols with stdlib defaults.

Backs BudgetCheck (spent), RateLimitCheck (windows), NonceCheck (seen set). A
Redis/DB store is a user-supplied adapter implementing the same Protocol;
nothing cloud lives in core.
"""

from __future__ import annotations

import time
from typing import Any, Protocol, runtime_checkable

__all__ = ["Clock", "SystemClock", "Store", "InMemoryStore"]


@runtime_checkable
class Clock(Protocol):
    """Monotonic-ish wall clock. Injected so checks stay pure/testable."""

    def now(self) -> float:
        """Seconds since epoch as a float."""
        ...


class SystemClock:
    """Default clock backed by ``time.time()``."""

    def now(self) -> float:
        return time.time()


@runtime_checkable
class Store(Protocol):
    """Minimal key/value + numeric + set store the stateful checks need.

    Deliberately tiny so a Redis/Postgres adapter is a thin wrapper.
    """

    def get(self, key: str, default: Any = None) -> Any: ...
    def set(self, key: str, value: Any) -> None: ...
    def incr_decimal(self, key: str, amount: Any) -> Any: ...
    def push_timestamp(self, key: str, ts: float, window: float) -> int: ...
    def add_once(self, key: str, member: str) -> bool: ...


class InMemoryStore:
    """Default in-process Store. Not shared across processes (use an adapter
    for that). Pure-python, no dependencies."""

    def __init__(self) -> None:
        self._kv: dict[str, Any] = {}
        self._windows: dict[str, list[float]] = {}
        self._sets: dict[str, set[str]] = {}

    def get(self, key: str, default: Any = None) -> Any:
        return self._kv.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._kv[key] = value

    def incr_decimal(self, key: str, amount: Any) -> Any:
        from decimal import Decimal

        current = self._kv.get(key, Decimal("0"))
        if not isinstance(current, Decimal):
            current = Decimal(str(current))
        current += Decimal(str(amount))
        self._kv[key] = current
        return current

    def push_timestamp(self, key: str, ts: float, window: float) -> int:
        """Append ts, prune entries older than ``window``, return current count."""
        bucket = self._windows.setdefault(key, [])
        cutoff = ts - window
        bucket[:] = [t for t in bucket if t > cutoff]
        bucket.append(ts)
        return len(bucket)

    def add_once(self, key: str, member: str) -> bool:
        """Return True if ``member`` was newly added (i.e. not a replay)."""
        bucket = self._sets.setdefault(key, set())
        if member in bucket:
            return False
        bucket.add(member)
        return True
