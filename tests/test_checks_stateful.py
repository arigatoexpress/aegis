"""Tests for the stateful/config checks: budget, rate-limit, nonce, allowlist,
verb, domain, capability, expiry, sequence."""

from __future__ import annotations

from decimal import Decimal

import pytest

from aegis import (
    ActionVerbCheck,
    AgentAction,
    BudgetCheck,
    CapabilityCheck,
    DomainCheck,
    ExpiryCheck,
    NonceCheck,
    RateLimitCheck,
    SequenceCheck,
    Severity,
    ToolAllowlistCheck,
)
from aegis.adapters import InMemoryStore
from aegis.check import Context
from aegis.checks.sequence import EXAMPLE_RULES


def _max_sev(reasons) -> Severity:
    return max((r.severity for r in reasons), default=Severity.NONE)


# --- budget -----------------------------------------------------------------
def test_budget_under_and_over():
    store = InMemoryStore()
    ctx = Context(store=store)
    chk = BudgetCheck(cap="100", budget_id="b1")
    # under cap -> allowed, records spend
    assert not list(chk.evaluate(AgentAction(name="x", amount=Decimal("40")), ctx))
    # cumulative now 40; 70 more would exceed 100 -> fires
    fired = list(chk.evaluate(AgentAction(name="x", amount=Decimal("70")), ctx))
    assert fired and "exceeds remaining" in fired[0].message


def test_budget_rejects_non_positive():
    chk = BudgetCheck(cap="100")
    fired = list(chk.evaluate(AgentAction(name="x", amount=Decimal("0")), Context(store=InMemoryStore())))
    assert fired and "non-positive" in fired[0].message


def test_budget_ignores_actions_without_amount():
    chk = BudgetCheck(cap="100")
    assert not list(chk.evaluate(AgentAction(name="x"), Context(store=InMemoryStore())))


# --- rate limit -------------------------------------------------------------
def test_rate_limit_window(fake_clock):
    store = InMemoryStore()
    ctx = Context(clock=fake_clock, store=store)
    chk = RateLimitCheck(max_calls=2, window_seconds=60, key="k")
    action = AgentAction(name="ping")
    assert not list(chk.evaluate(action, ctx))  # 1
    assert not list(chk.evaluate(action, ctx))  # 2
    over = list(chk.evaluate(action, ctx))  # 3 -> over
    assert over and _max_sev(over) >= Severity.HIGH  # fail-closed: blocks
    # advance past the window: count resets
    fake_clock.advance(61)
    assert not list(chk.evaluate(action, ctx))


def test_rate_limit_enforcement_knob(fake_clock):
    ctx = Context(clock=fake_clock, store=InMemoryStore())
    chk = RateLimitCheck(max_calls=1, window_seconds=60, key="k", enforcement="review")
    action = AgentAction(name="ping")
    assert not list(chk.evaluate(action, ctx))  # 1 ok
    over = list(chk.evaluate(action, ctx))  # 2 over
    assert over and _max_sev(over) is Severity.MEDIUM  # softened to review


# --- nonce / replay ---------------------------------------------------------
def test_nonce_replay():
    store = InMemoryStore()
    ctx_first = Context(store=store, data={"nonce": "abc"})
    ctx_again = Context(store=store, data={"nonce": "abc"})
    chk = NonceCheck()
    assert not list(chk.evaluate(AgentAction(name="x"), ctx_first))  # first use ok
    assert list(chk.evaluate(AgentAction(name="x"), ctx_again))  # replay blocked


def test_nonce_required_but_missing():
    chk = NonceCheck(require_nonce=True)
    fired = list(chk.evaluate(AgentAction(name="x"), Context(store=InMemoryStore())))
    assert fired and "missing required nonce" in fired[0].message


# --- tool allowlist ---------------------------------------------------------
@pytest.mark.parametrize(
    "name,fires",
    [("search", False), ("delete_db", True), ("unknown_tool", True)],
)
def test_tool_allowlist(name, fires):
    chk = ToolAllowlistCheck(allowed={"search", "summarize"}, denied={"delete_db"})
    fired = list(chk.evaluate(AgentAction(name=name), Context()))
    assert bool(fired) is fires
    if fires:
        # fail-closed: both not-allowed and denied block by default
        assert _max_sev(fired) >= Severity.HIGH


def test_tool_allowlist_enforcement_knob():
    review = ToolAllowlistCheck(allowed={"search"}, enforcement="review")
    fired = list(review.evaluate(AgentAction(name="unknown"), Context()))
    assert fired and _max_sev(fired) is Severity.MEDIUM
    warn = ToolAllowlistCheck(allowed={"search"}, enforcement="warn")
    fired_w = list(warn.evaluate(AgentAction(name="unknown"), Context()))
    assert fired_w and _max_sev(fired_w) is Severity.LOW


# --- action verb ------------------------------------------------------------
@pytest.mark.parametrize(
    "name,dry_run,fires",
    [
        ("send_email", False, True),
        ("delete_record", False, True),
        ("get_user", False, False),
        ("send_email", True, False),  # dry_run exempt
        ("simulate_send", False, False),  # sim-prefix exempt
    ],
)
def test_action_verb(name, dry_run, fires):
    chk = ActionVerbCheck()
    action = AgentAction(name=name, dry_run=dry_run)
    assert bool(list(chk.evaluate(action, Context()))) is fires


# --- domain -----------------------------------------------------------------
@pytest.mark.parametrize(
    "target,expect_block_label",
    [
        ("https://example.com/x", False),     # exact trusted
        ("https://examp1e.com", True),         # typosquat
        ("http://example.com", False),         # trusted host (non-https only review)
    ],
)
def test_domain_typosquat(target, expect_block_label):
    chk = DomainCheck(trusted={"example.com"})
    fired = list(chk.evaluate(AgentAction(name="send", target=target), Context()))
    has_typo = any("typosquat" in r.message for r in fired)
    assert has_typo is expect_block_label


def test_domain_subdomain_is_review():
    chk = DomainCheck(trusted={"example.com"})
    fired = list(chk.evaluate(AgentAction(target="https://api.example.com"), Context()))
    assert any("subdomain" in r.message for r in fired)
    # trusted-subdomain is a genuinely softer signal -> stays review, not block
    assert _max_sev(fired) is Severity.MEDIUM


def test_domain_non_https_flagged():
    chk = DomainCheck(trusted={"example.com"})
    fired = list(chk.evaluate(AgentAction(target="http://example.com"), Context()))
    assert any("non-https" in r.message for r in fired)


def test_domain_untrusted_blocks_by_default():
    chk = DomainCheck(trusted={"example.com"})
    fired = list(chk.evaluate(AgentAction(target="https://elsewhere.net"), Context()))
    assert fired and _max_sev(fired) >= Severity.HIGH
    assert any(r.evidence.get("rule") == "untrusted" for r in fired)


def test_domain_homograph_blocks_by_default():
    chk = DomainCheck(trusted={"example.com"})
    fired = list(chk.evaluate(AgentAction(target="https://exаmple.com"), Context()))  # cyrillic a
    assert fired and _max_sev(fired) >= Severity.HIGH


def test_domain_enforcement_knob_softens():
    chk = DomainCheck(trusted={"example.com"}, enforcement="review")
    fired = list(chk.evaluate(AgentAction(target="https://elsewhere.net"), Context()))
    assert fired and _max_sev(fired) is Severity.MEDIUM


# --- capability -------------------------------------------------------------
def test_capability_blocks_ungranted_commit():
    chk = CapabilityCheck("commit", grants={"commit": False})
    fired = list(chk.evaluate(AgentAction(name="x", committing=True), Context()))
    assert fired and "capability" in fired[0].message


def test_capability_allows_when_granted_or_dryrun():
    chk = CapabilityCheck("commit", grants={"commit": True})
    assert not list(chk.evaluate(AgentAction(committing=True), Context()))
    chk2 = CapabilityCheck("commit", grants={"commit": False})
    assert not list(chk2.evaluate(AgentAction(committing=True, dry_run=True), Context()))


# --- expiry -----------------------------------------------------------------
def test_expiry(fake_clock):
    ctx = Context(clock=fake_clock)
    chk = ExpiryCheck(expires_at=fake_clock.now() - 1)  # already expired
    assert list(chk.evaluate(AgentAction(name="x"), ctx))
    chk2 = ExpiryCheck(expires_at=fake_clock.now() + 1000)
    assert not list(chk2.evaluate(AgentAction(name="x"), ctx))


# --- sequence ---------------------------------------------------------------
def test_sequence_cooccurrence():
    chk = SequenceCheck(rules=EXAMPLE_RULES)
    plan = (AgentAction(name="read_secret"), AgentAction(name="send_external"))
    fired = list(chk.evaluate(AgentAction(name="plan", plan=plan), Context()))
    assert fired and "sends data externally" in fired[0].message


def test_sequence_empty_default_never_fires():
    chk = SequenceCheck()  # ships empty
    plan = (AgentAction(name="read_secret"), AgentAction(name="send_external"))
    assert not list(chk.evaluate(AgentAction(name="plan", plan=plan), Context()))
