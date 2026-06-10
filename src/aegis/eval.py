"""Golden-eval harness — 'evals are the spec' as a first-class library feature.

``ScenarioSpec`` declares an attacker move + the expected verdict; ``run_matrix``
runs a Guard over every spec and returns a pass/fail table. This is the
build_scenario_matrix/scenarios.py pattern promoted to a library primitive so a
user can assert their own policy's behavior.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .guard import Guard
from .types import AgentAction, Decision, Verdict

__all__ = ["ScenarioSpec", "ScenarioResult", "run_matrix", "format_matrix"]


@dataclass(frozen=True)
class ScenarioSpec:
    id: str
    title: str
    attacker_move: str
    expected: Verdict
    action: AgentAction | Mapping[str, Any]
    ctx: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScenarioResult:
    spec: ScenarioSpec
    decision: Decision
    passed: bool


def run_matrix(guard: Guard, specs: Sequence[ScenarioSpec]) -> list[ScenarioResult]:
    """Evaluate each spec; ``passed`` = decision.verdict matches spec.expected."""
    results: list[ScenarioResult] = []
    for spec in specs:
        if isinstance(spec.action, AgentAction):
            decision = guard.evaluate(spec.action, **dict(spec.ctx))
        else:
            decision = guard.evaluate_dict(spec.action, **dict(spec.ctx))
        results.append(
            ScenarioResult(
                spec=spec,
                decision=decision,
                passed=decision.verdict == spec.expected,
            )
        )
    return results


def format_matrix(results: Sequence[ScenarioResult]) -> str:
    """Render a compact pass/fail table for CLI output."""
    lines = [f"{'STATUS':<6} {'ID':<22} {'EXPECT':<7} {'GOT':<7} TITLE"]
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        lines.append(
            f"{status:<6} {r.spec.id:<22} {r.spec.expected.name:<7} "
            f"{r.decision.verdict.name:<7} {r.spec.title}"
        )
    passed = sum(1 for r in results if r.passed)
    lines.append(f"\n{passed}/{len(results)} scenarios passed")
    return "\n".join(lines)
