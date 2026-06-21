"""RunawayLoopCheck — detects repeated identical actions and short action cycles.

A loop guard is the natural complement to BudgetCheck and RateLimitCheck:
budget catches overspend, rate-limit catches volume, and loop catches the agent
stuck in a recursive or cyclic call pattern (e.g., ``search -> search -> search``
or ``read -> write -> read -> write``). Stateful via the injected Store + Clock.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from ..check import Context
from ..receipt import canonical_json
from ..types import AgentAction, Check, Enforcement, Reason, Severity, enforcement_severity

__all__ = ["RunawayLoopCheck"]


def _default_fingerprint(action: AgentAction) -> str:
    """Stable, order-independent fingerprint of the action surface that matters.

    Ignores non-deterministic / high-cardinality fields like ``meta`` by default,
    so a timestamp in metadata does not break loop detection.
    """
    payload = {
        "kind": action.kind,
        "name": action.name,
        "target": action.target,
        "args": dict(action.args) if action.args else {},
        "scan_text": action.scan_text,
    }
    return canonical_json(payload)


class RunawayLoopCheck(Check):
    id = "runaway_loop"
    default_severity = Severity.HIGH

    def __init__(
        self,
        *,
        window_seconds: float = 60.0,
        max_repeats: int = 3,
        min_cycle_length: int = 2,
        max_cycle_length: int = 4,
        key: str | None = None,
        enforcement: Enforcement = "block",
        severity: Severity | None = None,
        fingerprint: Callable[[AgentAction], str] | None = None,
    ) -> None:
        self.window = float(window_seconds)
        self.max_repeats = int(max_repeats)
        self.min_cycle_length = max(2, int(min_cycle_length))
        self.max_cycle_length = max(self.min_cycle_length, int(max_cycle_length))
        self.key = key
        self.fingerprint = fingerprint or _default_fingerprint
        # A runaway loop is a hard stop by default; the enforcement knob can soften.
        self.default_severity = severity or enforcement_severity(
            enforcement, floor=Severity.HIGH
        )

    def _resolve_key(self, action: AgentAction, ctx: Context) -> str:
        return self.key or str(ctx.get("loop_key") or action.name or "global")

    def _load_history(self, store_key: str, ctx: Context, now: float) -> list[tuple[float, str]]:
        if ctx.store is None:
            return []
        cutoff = now - self.window
        history = ctx.store.get(store_key, [])
        if not isinstance(history, list):
            return []
        # Each entry is [timestamp, fingerprint] (JSON round-trips lists, not tuples).
        return [(float(entry[0]), str(entry[1])) for entry in history if len(entry) >= 2 and float(entry[0]) > cutoff]

    def _save_history(self, store_key: str, ctx: Context, history: list[tuple[float, str]]) -> None:
        if ctx.store is None:
            return
        ctx.store.set(store_key, [[ts, fp] for ts, fp in history])

    def evaluate(self, action: AgentAction, ctx: Context) -> Iterable[Reason]:
        if ctx.store is None or ctx.clock is None:
            return ()

        now = ctx.clock.now()
        store_key = f"runaway_loop:{self._resolve_key(action, ctx)}"
        fp = self.fingerprint(action)

        history = self._load_history(store_key, ctx, now)
        history.append((now, fp))

        # 1. Exact consecutive repetition.
        repeat_count = 0
        for _ts, past_fp in reversed(history[:-1]):
            if past_fp == fp:
                repeat_count += 1
            else:
                break
        if repeat_count >= self.max_repeats:
            self._save_history(store_key, ctx, history)
            return (
                Reason(
                    check_id=self.id,
                    severity=self.default_severity,
                    message=f"runaway loop: action repeated {repeat_count + 1} times in {self.window}s",
                    evidence={
                        "key": self._resolve_key(action, ctx),
                        "repeat_count": repeat_count + 1,
                        "window_seconds": self.window,
                    },
                ),
            )

        # 2. Short action cycle (e.g. a, b, a, b).
        cycle = self._detect_cycle(history)
        if cycle is not None:
            self._save_history(store_key, ctx, history)
            return (
                Reason(
                    check_id=self.id,
                    severity=self.default_severity,
                    message=f"runaway loop: repeating cycle of length {len(cycle)} detected",
                    evidence={
                        "key": self._resolve_key(action, ctx),
                        "cycle_length": len(cycle),
                        "cycle_fingerprints": cycle,
                        "window_seconds": self.window,
                    },
                ),
            )

        self._save_history(store_key, ctx, history)
        return ()

    def _detect_cycle(self, history: list[tuple[float, str]]) -> list[str] | None:
        """Return the fingerprint cycle if the recent history contains it >=2x."""
        if len(history) < 2 * self.min_cycle_length:
            return None
        fingerprints = [fp for _ts, fp in history]
        for length in range(self.min_cycle_length, self.max_cycle_length + 1):
            if len(fingerprints) < 2 * length:
                continue
            candidate = fingerprints[-length:]
            prior = fingerprints[-(2 * length) : -length]
            if prior and prior == candidate:
                return candidate
        return None
