"""Notifier protocol + stdlib defaults.

Webhook/Slack/email notifiers are user-supplied or live in an optional extras
package — NEVER imported by core. The defaults here touch nothing but stdout /
the logging module / a supplied callable.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:  # pragma: no cover
    from ..types import Decision

__all__ = ["Notifier", "NoopNotifier", "ConsoleNotifier", "CallableNotifier"]

_log = logging.getLogger("aegis")


@runtime_checkable
class Notifier(Protocol):
    """Fired by the Guard on BLOCK/REVIEW decisions."""

    def notify(self, decision: Decision) -> None: ...


class NoopNotifier:
    """Default: does nothing. The firewall makes zero outbound calls."""

    def notify(self, decision: Decision) -> None:  # noqa: D401
        return None


class ConsoleNotifier:
    """Logs the decision via the stdlib logging module (no network)."""

    def __init__(self, level: int = logging.WARNING) -> None:
        self._level = level

    def notify(self, decision: Decision) -> None:
        _log.log(
            self._level,
            "aegis %s severity=%s checks=%s receipt=%s",
            decision.verdict.name,
            decision.severity.name,
            ",".join(decision.matched_checks) or "-",
            decision.receipt_id,
        )


class CallableNotifier:
    """Wraps any ``Callable[[Decision], None]`` (a user's webhook fn, etc.)."""

    def __init__(self, fn: Callable[[Decision], None]) -> None:
        self._fn = fn

    def notify(self, decision: Decision) -> None:
        self._fn(decision)
