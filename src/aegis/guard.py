"""Guard + Policy — the orchestrator and the composable check bundle.

Policy is a pure, ordered, named, composable bundle of Checks (compose with
``+``, subset with ``only``/``without``). Guard runs the policy fail-closed,
rolls up to a Decision, computes the tamper-evident receipt, redacts secrets out
of the persisted record, writes to the AuditSink, and fires the Notifier on
BLOCK/REVIEW. Every side-effect collaborator is an injected adapter with a stdlib
default — no cloud, no LLM SDK, no vendor.

Three usage modes:
  1. direct:     guard.check(action)  /  guard.evaluate(action)
  2. decorator:  @guard.protect       (wraps a tool fn; blocks raise GuardBlocked)
  3. middleware: guard.middleware(handler)  ->  callable(payload) -> result
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from .action import from_dict
from .check import Context, rollup, run_checks
from .receipt import derive_nonce, receipt_hash
from .redaction import DEFAULT_SECRET_KEYS, redact_mapping
from .types import AgentAction, Check, Decision, Reason, Severity, Verdict

from .adapters import (  # isort: skip
    AuditSink,
    Clock,
    InMemoryStore,
    NoopNotifier,
    Notifier,
    NullAuditSink,
    Store,
    SystemClock,
)

__all__ = ["Policy", "Guard", "GuardBlocked"]


class GuardBlocked(Exception):
    """Raised by the ``@guard.protect`` decorator when an action is blocked."""

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        msgs = "; ".join(r.message for r in decision.reasons) or "blocked"
        super().__init__(f"aegis blocked action: {msgs}")


class Policy:
    """An ordered, named, composable bundle of Checks. Holds no runtime state."""

    def __init__(self, checks: Sequence[Check], name: str = "default") -> None:
        self.checks: tuple[Check, ...] = tuple(checks)
        self.name = name

    def __add__(self, other: Policy) -> Policy:
        # de-dupe by id keeping order; later wins on id collision.
        merged: list[Check] = list(self.checks)
        seen: set[str] = {getattr(c, "id", c.__class__.__name__) for c in merged}
        for c in other.checks:
            cid = getattr(c, "id", c.__class__.__name__)
            if cid in seen:
                # later wins on id collision: remove the earlier occurrence
                merged = [x for x in merged if getattr(x, "id", x.__class__.__name__) != cid]
            merged.append(c)
            seen.add(cid)
        return Policy(merged, name=f"{self.name}+{other.name}")

    def without(self, *check_ids: str) -> Policy:
        drop = set(check_ids)
        return Policy(
            [c for c in self.checks if getattr(c, "id", "") not in drop],
            name=f"{self.name}-without",
        )

    def only(self, *check_ids: str) -> Policy:
        keep = set(check_ids)
        return Policy(
            [c for c in self.checks if getattr(c, "id", "") in keep],
            name=f"{self.name}-only",
        )

    def check_ids(self) -> tuple[str, ...]:
        return tuple(getattr(c, "id", c.__class__.__name__) for c in self.checks)

    def __iter__(self):
        return iter(self.checks)

    def __len__(self) -> int:
        return len(self.checks)

    def __repr__(self) -> str:
        return f"Policy({self.name!r}, checks={list(self.check_ids())})"


class Guard:
    """The orchestrator. All collaborators injected; stdlib defaults throughout.

    ``mode`` controls the enforcement posture used by the decorator/middleware:
      - "enforce" (default): BLOCK -> raise/short-circuit.
      - "monitor":            never blocks the call; only records the Decision.
    """

    def __init__(
        self,
        policy: Policy | Sequence[Check],
        *,
        store: Store | None = None,
        clock: Clock | None = None,
        audit: AuditSink | None = None,
        notifier: Notifier | None = None,
        redact_keys: frozenset[str] = DEFAULT_SECRET_KEYS,
        review_at: Severity = Severity.MEDIUM,
        block_at: Severity = Severity.HIGH,
        mode: str = "enforce",
        receipt_prefix: str = "",
    ) -> None:
        self.policy = policy if isinstance(policy, Policy) else Policy(policy)
        self.store: Store = store or InMemoryStore()
        self.clock: Clock = clock or SystemClock()
        self.audit: AuditSink = audit or NullAuditSink()
        self.notifier: Notifier = notifier or NoopNotifier()
        self.redact_keys = redact_keys
        self.review_at = review_at
        self.block_at = block_at
        if mode not in ("enforce", "monitor"):
            raise ValueError("mode must be 'enforce' or 'monitor'")
        self.mode = mode
        self.receipt_prefix = receipt_prefix

    # ------------------------------------------------------------------ core
    def _make_context(self, ctx_data: Mapping[str, Any] | None) -> Context:
        return Context(clock=self.clock, store=self.store, data=dict(ctx_data or {}))

    def evaluate(self, action: AgentAction, **ctx_data: Any) -> Decision:
        """Run the policy over ``action`` and return a Decision. Fail-closed."""
        ctx = self._make_context(ctx_data)
        reasons = run_checks(action, self.policy.checks, ctx)
        return self._finalize(action, reasons)

    # alias required by the public API ("direct .check(action)")
    def check(self, action: AgentAction, **ctx_data: Any) -> Decision:
        return self.evaluate(action, **ctx_data)

    def evaluate_dict(self, payload: Mapping[str, Any], **ctx_data: Any) -> Decision:
        """Untrusted-input boundary: coerce a mapping then evaluate."""
        return self.evaluate(from_dict(payload), **ctx_data)

    async def aevaluate(self, action: AgentAction, **ctx_data: Any) -> Decision:
        """Async-friendly wrapper around the same pure logic (no I/O await)."""
        return self.evaluate(action, **ctx_data)

    def _finalize(self, action: AgentAction, reasons: Iterable[Reason]) -> Decision:
        reasons = tuple(reasons)
        verdict, severity = rollup(
            reasons, review_at=self.review_at, block_at=self.block_at
        )
        matched = tuple(dict.fromkeys(r.check_id for r in reasons))  # order-preserve unique
        redactions = tuple(
            dict.fromkeys(r.redaction for r in reasons if r.redaction)
        )
        generated_at = datetime.now(UTC).isoformat()

        # Receipt is computed over a redacted, canonical view (secrets never
        # land in the audit hash input).
        receipt_subject = {
            "kind": action.kind,
            "name": action.name,
            "target": action.target,
            "amount": str(action.amount) if action.amount is not None else None,
            "args": redact_mapping(dict(action.args), self.redact_keys),
            "verdict": verdict.name,
            "severity": severity.name,
            "reasons": [
                {"check_id": r.check_id, "severity": r.severity.name, "message": r.message}
                for r in reasons
            ],
            "generated_at": generated_at,
        }
        rhash = receipt_hash(receipt_subject, prefix=self.receipt_prefix)
        rid = derive_nonce(rhash, generated_at)

        decision = Decision(
            allowed=verdict is not Verdict.BLOCK,
            verdict=verdict,
            severity=severity,
            reasons=reasons,
            matched_checks=matched,
            redactions=redactions,
            receipt_hash=rhash,
            receipt_id=rid,
            generated_at=generated_at,
        )

        # side-effects via adapters only
        try:
            self.audit.write(decision)
        except Exception:  # noqa: BLE001 - audit must never break the verdict
            pass
        if verdict in (Verdict.BLOCK, Verdict.REVIEW):
            try:
                self.notifier.notify(decision)
            except Exception:  # noqa: BLE001
                pass
        return decision

    # ------------------------------------------------------------- decorator
    def protect(
        self,
        *,
        kind: str = "tool_call",
        on_block: Callable[[Decision], Any] | None = None,
    ) -> Callable:
        """Decorator that guards a tool function.

        Builds an AgentAction from the call (``name`` = fn name, ``args`` =
        kwargs, ``scan_text`` = stringified args). On BLOCK in enforce mode it
        raises ``GuardBlocked`` (or calls ``on_block`` if given).
        """

        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                action = AgentAction(
                    kind=kind,  # type: ignore[arg-type]
                    name=fn.__name__,
                    args=dict(kwargs),
                    scan_text="\n".join(str(a) for a in (*args, *kwargs.values())),
                )
                decision = self.evaluate(action)
                if not decision.allowed and self.mode == "enforce":
                    if on_block is not None:
                        return on_block(decision)
                    raise GuardBlocked(decision)
                return fn(*args, **kwargs)

            wrapper.aegis_guard = self  # type: ignore[attr-defined]
            return wrapper

        return decorator

    # ------------------------------------------------------------ middleware
    def middleware(
        self,
        handler: Callable[[Mapping[str, Any]], Any],
        *,
        on_block: Callable[[Decision, Mapping[str, Any]], Any] | None = None,
    ) -> Callable[[Mapping[str, Any]], Any]:
        """Wrap a payload-handling callable.

        Returns ``callable(payload) -> result``: evaluates the payload as an
        AgentAction; if blocked (enforce mode) returns ``on_block(decision,
        payload)`` (default: the Decision dict), else calls ``handler(payload)``.
        """

        def wrapped(payload: Mapping[str, Any]) -> Any:
            decision = self.evaluate_dict(payload)
            if not decision.allowed and self.mode == "enforce":
                if on_block is not None:
                    return on_block(decision, payload)
                return {"blocked": True, "decision": decision.to_dict()}
            return handler(payload)

        return wrapped
