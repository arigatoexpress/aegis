"""Tests for RunawayLoopCheck — repeated-action / cycle detection."""

from __future__ import annotations

from aegis import AgentAction, RunawayLoopCheck, Severity
from aegis.adapters import InMemoryStore
from aegis.check import Context


def _reasons(check, action, context):
    return list(check.evaluate(action, context))


def _seed(store, clock, check, action, times: int, ctx_key: str = "default"):
    """Submit the same action ``times`` times to populate loop history."""
    ctx = Context(clock=clock, store=store, data={"loop_key": ctx_key})
    for _ in range(times):
        list(check.evaluate(action, ctx))


# --- repetition detection -----------------------------------------------------
def test_allows_varied_actions(fake_clock):
    store = InMemoryStore()
    ctx = Context(clock=fake_clock, store=store)
    check = RunawayLoopCheck(window_seconds=60, max_repeats=2)
    assert not _reasons(check, AgentAction(name="a"), ctx)
    assert not _reasons(check, AgentAction(name="b"), ctx)
    assert not _reasons(check, AgentAction(name="a"), ctx)


def test_blocks_after_max_repeats(fake_clock):
    store = InMemoryStore()
    check = RunawayLoopCheck(window_seconds=60, max_repeats=2)
    action = AgentAction(name="ping")
    _seed(store, fake_clock, check, action, 2, ctx_key="k")

    fired = _reasons(check, action, Context(clock=fake_clock, store=store, data={"loop_key": "k"}))
    assert fired
    assert all(r.severity >= Severity.HIGH for r in fired)
    assert any("repeated" in r.message for r in fired)


def test_repetition_window_prunes_old_entries(fake_clock):
    store = InMemoryStore()
    check = RunawayLoopCheck(window_seconds=60, max_repeats=2)
    action = AgentAction(name="ping")
    _seed(store, fake_clock, check, action, 2, ctx_key="k")

    # Old entries age out, so the next identical action is allowed again.
    fake_clock.advance(61)
    assert not _reasons(check, action, Context(clock=fake_clock, store=store, data={"loop_key": "k"}))


# --- cycle detection ----------------------------------------------------------
def test_blocks_short_cycles(fake_clock):
    store = InMemoryStore()
    check = RunawayLoopCheck(window_seconds=60, max_repeats=10, min_cycle_length=2)
    a = AgentAction(name="a")
    b = AgentAction(name="b")

    # Seed a, b, a, b — already two full cycles of (a, b).
    ctx = Context(clock=fake_clock, store=store, data={"loop_key": "k"})
    for act in (a, b, a, b):
        list(check.evaluate(act, ctx))

    # The next action in the pattern triggers the loop detector.
    fired = _reasons(check, a, ctx)
    assert fired
    assert any("cycle" in r.message for r in fired)


def test_cycle_detection_honors_min_length(fake_clock):
    store = InMemoryStore()
    # min_cycle_length=3 means a 2-step back-and-forth should not be flagged.
    check = RunawayLoopCheck(window_seconds=60, max_repeats=10, min_cycle_length=3)
    a = AgentAction(name="a")
    b = AgentAction(name="b")

    ctx = Context(clock=fake_clock, store=store, data={"loop_key": "k"})
    for act in (a, b, a, b, a):
        assert not list(check.evaluate(act, ctx))


# --- knobs -------------------------------------------------------------------
def test_enforcement_knob_softens(fake_clock):
    store = InMemoryStore()
    check = RunawayLoopCheck(window_seconds=60, max_repeats=2, enforcement="review")
    action = AgentAction(name="ping")
    _seed(store, fake_clock, check, action, 2, ctx_key="k")

    fired = _reasons(check, action, Context(clock=fake_clock, store=store, data={"loop_key": "k"}))
    assert fired
    assert all(r.severity is Severity.MEDIUM for r in fired)


def test_warn_mode(fake_clock):
    store = InMemoryStore()
    check = RunawayLoopCheck(window_seconds=60, max_repeats=2, enforcement="warn")
    action = AgentAction(name="ping")
    _seed(store, fake_clock, check, action, 2, ctx_key="k")

    fired = _reasons(check, action, Context(clock=fake_clock, store=store, data={"loop_key": "k"}))
    assert fired
    assert all(r.severity is Severity.LOW for r in fired)


# --- fingerprint sensitivity --------------------------------------------------
def test_same_name_different_args_not_a_loop(fake_clock):
    store = InMemoryStore()
    check = RunawayLoopCheck(window_seconds=60, max_repeats=2)
    ctx = Context(clock=fake_clock, store=store, data={"loop_key": "k"})

    list(check.evaluate(AgentAction(name="search", args={"q": "x"}), ctx))
    list(check.evaluate(AgentAction(name="search", args={"q": "x"}), ctx))
    assert not _reasons(check, AgentAction(name="search", args={"q": "y"}), ctx)


def test_distinguishes_keys(fake_clock):
    store = InMemoryStore()
    check = RunawayLoopCheck(window_seconds=60, max_repeats=2)
    action = AgentAction(name="ping")

    _seed(store, fake_clock, check, action, 3, ctx_key="a")
    # Same action shape, different loop_key, should be allowed.
    assert not _reasons(check, action, Context(clock=fake_clock, store=store, data={"loop_key": "b"}))


# --- failure mode -------------------------------------------------------------
def test_no_store_or_clock_is_noop():
    check = RunawayLoopCheck(window_seconds=60, max_repeats=1)
    assert not _reasons(check, AgentAction(name="x"), Context())
