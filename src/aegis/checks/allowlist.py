"""ToolAllowlistCheck + ActionVerbCheck — the generic tool/action gates.

Default-deny tool/method names, and a side-effect-verb heuristic with a dry-run
exemption. Verb/tool sets are injected per-deployment, never hardcoded.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..check import Context
from ..types import AgentAction, Check, Enforcement, Reason, Severity, enforcement_severity

__all__ = ["ToolAllowlistCheck", "ActionVerbCheck", "DEFAULT_SIDE_EFFECT_VERBS"]

# Generic base verb set (no domain vocabulary). Domain verb packs are injectable.
DEFAULT_SIDE_EFFECT_VERBS: frozenset[str] = frozenset(
    {
        "send",
        "transfer",
        "post",
        "purchase",
        "buy",
        "pay",
        "install",
        "execute",
        "run",
        "delete",
        "remove",
        "drop",
        "publish",
        "deploy",
        "write",
        "update",
        "create",
        "modify",
        "grant",
        "revoke",
        "email",
        "upload",
        "push",
    }
)

_SPLIT = re.compile(r"[_\-/.\s]+")
# Leading tokens that mark a non-committing / preview step (no real side effect).
# "draft"/"compose"/"prepare" build something without enacting it; read-style
# verbs are inherently side-effect-free.
_SIM_PREFIXES = (
    "dry",
    "sim",
    "simulate",
    "preview",
    "test",
    "estimate",
    "read",
    "get",
    "list",
    "draft",
    "compose",
    "prepare",
    "plan",
)


class ToolAllowlistCheck(Check):
    id = "tool_allowlist"
    default_severity = Severity.HIGH

    def __init__(
        self,
        *,
        allowed: Iterable[str] | None = None,
        denied: Iterable[str] | None = None,
        enforcement: Enforcement = "block",
        unknown_severity: Severity | None = None,
        denied_severity: Severity | None = None,
    ) -> None:
        self.allowed = frozenset(allowed) if allowed is not None else None
        self.denied = frozenset(denied or ())
        self.enforcement = enforcement
        # A firewall fails closed: a tool that is explicitly denied or not in the
        # allowlist BLOCKS by default. ``enforcement`` softens both to review/warn
        # in one knob; an explicit severity arg still wins for fine control.
        default_sev = enforcement_severity(enforcement, floor=Severity.HIGH)
        self.unknown_severity = unknown_severity or default_sev
        self.denied_severity = denied_severity or default_sev

    def evaluate(self, action: AgentAction, ctx: Context) -> Iterable[Reason]:
        name = action.name
        if not name:
            return ()
        if name in self.denied:
            return (
                Reason(
                    check_id=self.id,
                    severity=self.denied_severity,
                    message=f"tool '{name}' is explicitly denied",
                    evidence={"name": name, "rule": "denied"},
                ),
            )
        if self.allowed is not None and name not in self.allowed:
            return (
                Reason(
                    check_id=self.id,
                    severity=self.unknown_severity,
                    message=f"tool '{name}' not in allowlist",
                    evidence={"name": name, "rule": "not_allowed"},
                ),
            )
        return ()


class ActionVerbCheck(Check):
    id = "action_verb"
    default_severity = Severity.HIGH

    def __init__(
        self,
        verbs: Iterable[str] | None = None,
        *,
        severity: Severity | None = None,
    ) -> None:
        self.verbs = frozenset(v.lower() for v in (verbs or DEFAULT_SIDE_EFFECT_VERBS))
        self.default_severity = severity or Severity.HIGH

    def evaluate(self, action: AgentAction, ctx: Context) -> Iterable[Reason]:
        if not action.name:
            return ()
        tokens = [t.lower() for t in _SPLIT.split(action.name) if t]
        if not tokens:
            return ()
        # simulation-prefix / dry_run exemption
        if action.dry_run or (tokens and tokens[0] in _SIM_PREFIXES):
            return ()
        side_effect = [t for t in tokens if t in self.verbs]
        if side_effect:
            return (
                Reason(
                    check_id=self.id,
                    severity=self.default_severity,
                    message=f"side-effect action '{action.name}' ({', '.join(side_effect)}) without dry_run",
                    evidence={"verbs": side_effect, "name": action.name},
                ),
            )
        return ()
