"""CapabilityCheck + ExpiryCheck — privileged-action and mandate-expiry gates.

CapabilityCheck generalizes the source repos' privileged-write gate: a
committing action requested while the capability grant is False and not in
dry_run is blocked. ExpiryCheck blocks a mandate used past its ``expires_at``.
Both fully domain-neutral.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from ..check import Context
from ..types import AgentAction, Check, Enforcement, Reason, Severity, enforcement_severity

__all__ = ["CapabilityCheck", "ExpiryCheck"]


class CapabilityCheck(Check):
    id = "capability"
    default_severity = Severity.CRITICAL

    def __init__(
        self,
        capability: str = "commit",
        *,
        grants: Mapping[str, bool] | None = None,
        enforcement: Enforcement = "block",
        severity: Severity | None = None,
    ) -> None:
        self.capability = capability
        self.grants = dict(grants or {})
        self.enforcement = enforcement
        # A committing action without the grant is the highest-stakes default-deny:
        # block at CRITICAL by default; enforcement can soften it.
        self.default_severity = severity or enforcement_severity(
            enforcement, floor=Severity.CRITICAL
        )

    def evaluate(self, action: AgentAction, ctx: Context) -> Iterable[Reason]:
        if not action.committing or action.dry_run:
            return ()
        # ctx-supplied grants override constructor grants per-call.
        grants = ctx.get("grants", self.grants) or {}
        granted = bool(grants.get(self.capability, False))
        if granted:
            return ()
        return (
            Reason(
                check_id=self.id,
                severity=self.default_severity,
                message=f"committing action requires capability '{self.capability}' which is not granted",
                evidence={"capability": self.capability, "granted": granted},
            ),
        )


class ExpiryCheck(Check):
    id = "expiry"
    default_severity = Severity.HIGH

    def __init__(
        self,
        expires_at: float | None = None,
        *,
        severity: Severity | None = None,
    ) -> None:
        self.expires_at = expires_at
        self.default_severity = severity or Severity.HIGH

    def evaluate(self, action: AgentAction, ctx: Context) -> Iterable[Reason]:
        expires_at = self.expires_at
        if expires_at is None:
            expires_at = ctx.get("expires_at") or action.meta.get("expires_at")
        if expires_at is None:
            return ()
        if ctx.clock is None:
            return ()
        now = ctx.clock.now()
        if now > float(expires_at):
            return (
                Reason(
                    check_id=self.id,
                    severity=self.default_severity,
                    message=f"mandate expired ({now:.0f} > {float(expires_at):.0f})",
                    evidence={"now": now, "expires_at": float(expires_at)},
                ),
            )
        return ()
