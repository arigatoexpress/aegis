"""SequenceCheck — guard the agent's PLAN, not just one call.

Generalized ``_check_behavioral_sequence``: scan an ordered list of planned
AgentActions for dangerous co-occurrence or adjacency of risky steps, supplied as
config. Mechanism generic; ships with an EMPTY default ruleset plus a documented
example so it never fires unless a caller opts in.

Ruleset shape::

    rules = [
        # co-occurrence: both names appear anywhere in the plan
        {"kind": "cooccur", "names": ["read_secret", "send"], "severity": "HIGH",
         "message": "reads a secret then sends data"},
        # adjacency: name_a immediately followed by name_b
        {"kind": "adjacent", "a": "disable_guard", "b": "execute", "severity": "CRITICAL",
         "message": "disables guard then executes"},
    ]
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from ..check import Context
from ..types import AgentAction, Check, Reason, Severity

__all__ = ["SequenceCheck", "EXAMPLE_RULES"]

# Documented example a caller can copy. NOT applied by default.
EXAMPLE_RULES: tuple[dict[str, Any], ...] = (
    {
        "kind": "cooccur",
        "names": ["read_secret", "send_external"],
        "severity": "HIGH",
        "message": "plan reads a secret and then sends data externally",
    },
    {
        "kind": "adjacent",
        "a": "disable_guard",
        "b": "execute",
        "severity": "CRITICAL",
        "message": "plan disables a guard immediately before executing",
    },
)


class SequenceCheck(Check):
    id = "sequence"
    default_severity = Severity.HIGH

    def __init__(self, rules: Sequence[dict[str, Any]] | None = None) -> None:
        self.rules = tuple(rules or ())

    def evaluate(self, action: AgentAction, ctx: Context) -> Iterable[Reason]:
        plan = action.plan
        if not plan or not self.rules:
            return ()
        names = [step.name for step in plan]
        reasons: list[Reason] = []
        for rule in self.rules:
            sev = Severity.coerce(rule.get("severity", "HIGH"))
            kind = rule.get("kind", "cooccur")
            if kind == "cooccur":
                wanted = rule.get("names", [])
                if wanted and all(w in names for w in wanted):
                    reasons.append(
                        Reason(
                            check_id=self.id,
                            severity=sev,
                            message=rule.get("message", f"dangerous co-occurrence {wanted}"),
                            evidence={"rule": "cooccur", "names": wanted},
                        )
                    )
            elif kind == "adjacent":
                a, b = rule.get("a"), rule.get("b")
                for i in range(len(names) - 1):
                    if names[i] == a and names[i + 1] == b:
                        reasons.append(
                            Reason(
                                check_id=self.id,
                                severity=sev,
                                message=rule.get("message", f"dangerous adjacency {a}->{b}"),
                                evidence={"rule": "adjacent", "a": a, "b": b, "at": i},
                            )
                        )
                        break
        return reasons
