"""The composition engine: Context, run_checks, and rollup.

This is the spine extracted from the source repos'
``evaluate_intent``/``evaluate_attempt``/``native_preflight`` — minus any
domain or vendor assumption. ``rollup`` is the single deterministic worst-case
collapse that replaced three near-identical copies.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from .types import AgentAction, Check, Reason, Severity, Verdict

__all__ = ["Context", "run_checks", "rollup"]


@dataclass
class Context:
    """Per-evaluation context handed to every Check.

    Carries the injected adapters (clock/store) and a free-form scratch ``data``
    map so a caller can pass per-call knobs (budget id, capability grants, rate
    keys) without widening every check signature.
    """

    clock: Any = None
    store: Any = None
    data: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)


def run_checks(action: AgentAction, checks: Sequence[Check], ctx: Context) -> list[Reason]:
    """Run every check in order, fail-closed.

    A check that raises does NOT propagate; it becomes a CRITICAL Reason so a
    buggy or malicious check can never silently fail-open the firewall.
    """
    reasons: list[Reason] = []
    for chk in checks:
        try:
            produced = chk.evaluate(action, ctx)
            if produced:
                reasons.extend(produced)
        except Exception as exc:  # noqa: BLE001 - fail-closed by design
            cid = getattr(chk, "id", chk.__class__.__name__)
            reasons.append(
                Reason(
                    check_id=cid,
                    severity=Severity.CRITICAL,
                    message=f"check '{cid}' raised {type(exc).__name__}: {exc}",
                    evidence={"error": type(exc).__name__},
                )
            )
    return reasons


def rollup(
    reasons: Iterable[Reason],
    *,
    review_at: Severity = Severity.MEDIUM,
    block_at: Severity = Severity.HIGH,
) -> tuple[Verdict, Severity]:
    """Deterministic worst-case collapse, threshold-configurable.

    Max-severity reason at/above ``block_at`` -> BLOCK, at/above ``review_at`` ->
    REVIEW, else ALLOW. Pure; usable standalone.
    """
    worst = Severity.NONE
    for r in reasons:
        if r.severity > worst:
            worst = r.severity
    if worst >= block_at:
        return Verdict.BLOCK, worst
    if worst >= review_at:
        return Verdict.REVIEW, worst
    return Verdict.ALLOW, worst
