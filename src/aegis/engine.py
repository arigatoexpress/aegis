"""Engine surface: Guard + Policy + the composition primitives.

Thin re-export module so callers can ``from aegis.engine import Guard, Policy``.
The implementation lives in ``guard.py`` (orchestrator) and ``check.py``
(run_checks/rollup). Kept as a separate name because the design references both
``guard.py`` and ``engine.py``; this module is the single import point for the
'runs a list of checks over an action, aggregates a Decision' engine.
"""

from __future__ import annotations

from .check import Context, rollup, run_checks
from .guard import Guard, GuardBlocked, Policy

__all__ = [
    "Guard",
    "Policy",
    "GuardBlocked",
    "Context",
    "run_checks",
    "rollup",
]
