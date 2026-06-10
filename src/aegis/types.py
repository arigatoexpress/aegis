"""Frozen, stdlib-only shared types: the subject, the finding, the verdict.

Unifies the three source repos' parallel verdict objects
(PolicyDecision / DomainDecision / SentinelDecision) into ONE ``Decision`` +
``Reason`` shape, and fixes their shared latent bug: severity now lives on each
``Reason`` instead of being string-sniffed out of blocker text.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from enum import IntEnum
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .check import Context

__all__ = [
    "Severity",
    "Verdict",
    "Enforcement",
    "enforcement_severity",
    "AgentAction",
    "Reason",
    "Decision",
    "Check",
]


class Severity(IntEnum):
    """Ordered severity. Comparable so ``rollup`` can take a max cheaply."""

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def coerce(cls, value: Severity | str | int) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]


# Per-check enforcement knob. A firewall fails closed, so default-deny / limit /
# grant checks default to ``"block"``. The three modes map onto the severity a
# fired finding emits, which then rolls up against the Guard's thresholds
# (REVIEW at MEDIUM, BLOCK at HIGH by default):
#   block  -> HIGH    (allowed=False)
#   review -> MEDIUM  (allowed=True, human-gate)
#   warn   -> LOW     (allowed=True, recorded only)
Enforcement = Literal["block", "review", "warn"]

_ENFORCEMENT_SEVERITY: dict[str, Severity] = {
    "block": Severity.HIGH,
    "review": Severity.MEDIUM,
    "warn": Severity.LOW,
}


def enforcement_severity(
    mode: Enforcement | str, *, floor: Severity = Severity.NONE
) -> Severity:
    """Map an enforcement mode to the Severity a fired finding should carry.

    ``floor`` lets a check keep a naturally-higher severity for ``block`` (e.g.
    a missing capability grant stays CRITICAL): the returned severity is the max
    of the mapped value and the floor, but only when blocking. ``review``/``warn``
    always downgrade so the operator's intent to soften is honored.
    """
    key = str(mode).strip().lower()
    sev = _ENFORCEMENT_SEVERITY.get(key)
    if sev is None:
        raise ValueError(f"enforcement must be one of block|review|warn, got {mode!r}")
    if key == "block" and floor > sev:
        return floor
    return sev


class Verdict(IntEnum):
    """Three-tier outcome. REVIEW is the human-gate (1-click approval) tier."""

    ALLOW = 0
    REVIEW = 1
    BLOCK = 2


# ``kind`` values describe the three guarded surfaces.
ActionKind = Literal["tool_call", "message", "model_output"]


def _coerce_decimal(value: Any) -> Decimal | None:
    """Safely coerce to Decimal; never raise on bad input (fail-closed callers)."""
    if value is None or value == "":
        return None
    if isinstance(value, Decimal):
        return value
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None


@dataclass(frozen=True)
class AgentAction:
    """The single generic subject every check evaluates.

    Replaces the source repos' PaymentAttempt / normalized-intent /
    provider-request with one neutral shape covering all three guarded surfaces.
    ``scan_text`` is the unified free-text target so detectors run once.
    """

    kind: ActionKind = "tool_call"
    name: str = ""
    scan_text: str = ""
    args: Mapping[str, Any] = field(default_factory=dict)
    target: str | None = None
    amount: Decimal | None = None
    committing: bool = False
    dry_run: bool = False
    plan: tuple[AgentAction, ...] = ()
    meta: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> AgentAction:
        """Alias-tolerant, safe coercion from an untrusted mapping.

        Lives here for import-cycle reasons; ``action.from_dict`` is the public
        helper and delegates to this.
        """
        from .action import from_dict as _from_dict

        return _from_dict(payload)


@dataclass(frozen=True)
class Reason:
    """The atomic finding. Unifies blockers / warnings / risk_flags.

    Severity lives ON the Reason (fixing the fragile ``'secret' in blocker_text``
    inference in all three source repos). ``rollup`` collapses reasons -> Decision.
    """

    check_id: str
    severity: Severity
    message: str
    evidence: Mapping[str, Any] = field(default_factory=dict)
    redaction: str | None = None

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "severity": self.severity.name,
            "message": self.message,
            "evidence": dict(self.evidence),
            "redaction": self.redaction,
        }


@dataclass(frozen=True)
class Decision:
    """The unified verdict + audit receipt + redaction list.

    ``allowed == (verdict is not BLOCK)``. ``to_dict`` is wire-stable for any
    transport.
    """

    allowed: bool
    verdict: Verdict
    severity: Severity
    reasons: tuple[Reason, ...]
    matched_checks: tuple[str, ...]
    redactions: tuple[str, ...]
    receipt_hash: str
    receipt_id: str
    generated_at: str

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "verdict": self.verdict.name,
            "severity": self.severity.name,
            "reasons": [r.to_dict() for r in self.reasons],
            "matched_checks": list(self.matched_checks),
            "redactions": list(self.redactions),
            "receipt_hash": self.receipt_hash,
            "receipt_id": self.receipt_id,
            "generated_at": self.generated_at,
        }


class Check(ABC):
    """The extension seam and the unit of composability.

    Every shipped check subclasses this. A user adds a domain-specific check by
    subclassing and dropping it into a ``Policy``. Each Check is independently
    constructible and callable in isolation::

        list(check.evaluate(action, ctx))

    Implementations MUST be pure and deterministic: no I/O, no clock except via
    ``ctx``, no mutation of ``action``.
    """

    id: str = "check"
    default_severity: Severity = Severity.MEDIUM

    @abstractmethod
    def evaluate(self, action: AgentAction, ctx: Context) -> Iterable[Reason]:
        """Return 0+ Reasons. Returning none == this check passed."""
        raise NotImplementedError
