"""BudgetCheck — unit-agnostic running cap.

Decimal compare ``amount > remaining`` where ``remaining = max(cap - spent, 0)``.
Renamed off any currency; the cap mechanism was already generic in all three
source repos. Spent is tracked via the injected Store keyed by a budget id, so it
works in-process or behind a shared adapter.
"""

from __future__ import annotations

from collections.abc import Iterable
from decimal import Decimal, InvalidOperation

from ..check import Context
from ..types import AgentAction, Check, Reason, Severity

__all__ = ["BudgetCheck"]


class BudgetCheck(Check):
    id = "budget"
    default_severity = Severity.HIGH

    def __init__(
        self,
        cap: Decimal | str | int | float,
        *,
        budget_id: str = "default",
        commit: bool = True,
        severity: Severity | None = None,
    ) -> None:
        self.cap = Decimal(str(cap))
        self.budget_id = budget_id
        self.commit = commit  # if True, allowed spend is recorded to the store
        self.default_severity = severity or Severity.HIGH

    def _key(self) -> str:
        return f"budget:spent:{self.budget_id}"

    def evaluate(self, action: AgentAction, ctx: Context) -> Iterable[Reason]:
        if action.amount is None:
            return ()
        try:
            amount = Decimal(str(action.amount))
        except (InvalidOperation, ValueError, TypeError):
            return (
                Reason(
                    check_id=self.id,
                    severity=self.default_severity,
                    message="non-numeric amount",
                    evidence={"amount": str(action.amount)},
                ),
            )

        if amount <= 0:
            return (
                Reason(
                    check_id=self.id,
                    severity=self.default_severity,
                    message="non-positive amount",
                    evidence={"amount": str(amount)},
                ),
            )

        store = ctx.store
        spent = Decimal("0")
        if store is not None:
            raw = store.get(self._key(), Decimal("0"))
            spent = raw if isinstance(raw, Decimal) else Decimal(str(raw))
        remaining = self.cap - spent
        if remaining < 0:
            remaining = Decimal("0")

        if amount > remaining:
            return (
                Reason(
                    check_id=self.id,
                    severity=self.default_severity,
                    message=f"amount {amount} exceeds remaining budget {remaining}",
                    evidence={
                        "amount": str(amount),
                        "remaining": str(remaining),
                        "cap": str(self.cap),
                        "spent": str(spent),
                    },
                ),
            )

        if self.commit and store is not None and not action.dry_run:
            store.incr_decimal(self._key(), amount)
        return ()
