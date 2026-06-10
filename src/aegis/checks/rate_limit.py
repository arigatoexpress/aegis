"""RateLimitCheck + NonceCheck — the real limiter and the replay guard.

The source repos only had these as config booleans. RateLimitCheck is a true
time-windowed limiter (deque of timestamps per key via the injected Store +
Clock). NonceCheck is a process-once idempotency/replay guard (Store-backed set).
Both work in-process or behind a shared adapter in Docker.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..check import Context
from ..types import AgentAction, Check, Enforcement, Reason, Severity, enforcement_severity

__all__ = ["RateLimitCheck", "NonceCheck"]


def _resolve_key(action: AgentAction, ctx: Context, ctx_key: str, default: str) -> str:
    """Pick the rate/nonce key: ctx override -> action.meta -> name -> default."""
    if ctx.get(ctx_key):
        return str(ctx.get(ctx_key))
    if action.meta.get(ctx_key):
        return str(action.meta[ctx_key])
    return action.name or default


class RateLimitCheck(Check):
    id = "rate_limit"
    default_severity = Severity.HIGH

    def __init__(
        self,
        max_calls: int,
        window_seconds: float,
        *,
        key: str | None = None,
        enforcement: Enforcement = "block",
        severity: Severity | None = None,
    ) -> None:
        self.max_calls = int(max_calls)
        self.window = float(window_seconds)
        self.key = key  # static key; if None, resolved per-action
        self.enforcement = enforcement
        # Exceeding a rate limit is a hard stop by default (fail closed). The
        # README claims rate-limit blocks; the enforcement knob can soften it.
        self.default_severity = severity or enforcement_severity(
            enforcement, floor=Severity.HIGH
        )

    def evaluate(self, action: AgentAction, ctx: Context) -> Iterable[Reason]:
        if ctx.store is None or ctx.clock is None:
            return ()
        key = self.key or _resolve_key(action, ctx, "rate_key", "global")
        store_key = f"rate:{key}"
        count = ctx.store.push_timestamp(store_key, ctx.clock.now(), self.window)
        if count > self.max_calls:
            return (
                Reason(
                    check_id=self.id,
                    severity=self.default_severity,
                    message=f"rate limit exceeded: {count} > {self.max_calls} per {self.window}s for '{key}'",
                    evidence={"key": key, "count": count, "limit": self.max_calls},
                ),
            )
        return ()


class NonceCheck(Check):
    id = "nonce_replay"
    default_severity = Severity.HIGH

    def __init__(
        self,
        *,
        key: str | None = None,
        require_nonce: bool = False,
        enforcement: Enforcement = "block",
        severity: Severity | None = None,
    ) -> None:
        self.key = key
        self.require_nonce = require_nonce
        self.enforcement = enforcement
        # A replayed (or missing-but-required) nonce blocks by default.
        self.default_severity = severity or enforcement_severity(
            enforcement, floor=Severity.HIGH
        )

    def evaluate(self, action: AgentAction, ctx: Context) -> Iterable[Reason]:
        nonce = ctx.get("nonce") or action.meta.get("nonce")
        if not nonce:
            if self.require_nonce:
                return (
                    Reason(
                        check_id=self.id,
                        severity=self.default_severity,
                        message="missing required nonce",
                        evidence={},
                    ),
                )
            return ()
        if ctx.store is None:
            return ()
        scope = self.key or "nonce"
        fresh = ctx.store.add_once(f"nonce:{scope}", str(nonce))
        if not fresh:
            return (
                Reason(
                    check_id=self.id,
                    severity=self.default_severity,
                    message=f"replayed nonce '{nonce}'",
                    evidence={"nonce": str(nonce)},
                ),
            )
        return ()
