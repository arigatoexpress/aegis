"""Shared fixtures/helpers for the aegis test suite."""

from __future__ import annotations

import pytest

from aegis.adapters import InMemoryStore, SystemClock
from aegis.check import Context


class FakeClock:
    """Manually-advanced clock for deterministic rate-limit tests."""

    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def now(self) -> float:
        return self.t

    def advance(self, seconds: float) -> FakeClock:
        self.t += seconds
        return self


@pytest.fixture
def ctx() -> Context:
    return Context(clock=SystemClock(), store=InMemoryStore(), data={})


@pytest.fixture
def fake_clock() -> FakeClock:
    return FakeClock()


def reasons(check, action, context) -> list:
    return list(check.evaluate(action, context))
