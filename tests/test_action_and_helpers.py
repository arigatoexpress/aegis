"""Tests for action normalization, receipts, and redaction helpers."""

from __future__ import annotations

from decimal import Decimal

from aegis import AgentAction, apply_spans, canonical_json, receipt_hash, redact_mapping
from aegis.action import concat_text, from_dict, iter_values
from aegis.receipt import derive_nonce


# --- from_dict normalization ------------------------------------------------
def test_from_dict_alias_collapse():
    a = from_dict({"type": "message", "prompt": "hi", "url": "https://x.com", "value": "5"})
    assert a.kind == "message"
    assert a.name == ""  # 'type' is a name alias but maps kind first; here name unset
    assert "hi" in a.scan_text
    assert a.target == "https://x.com"
    assert a.amount == Decimal("5")


def test_from_dict_name_alias():
    a = from_dict({"tool": "search", "args": {"q": "x"}})
    assert a.name == "search"
    assert a.args == {"q": "x"}


def test_from_dict_bad_amount_is_none_not_raise():
    a = from_dict({"name": "x", "amount": "not-a-number"})
    assert a.amount is None


def test_from_dict_unknown_keys_become_args():
    a = from_dict({"name": "x", "foo": 1, "bar": "y"})
    assert a.args == {"foo": 1, "bar": "y"}


def test_from_dict_nested_plan():
    a = from_dict({"name": "plan", "plan": [{"name": "a"}, {"name": "b"}]})
    assert tuple(p.name for p in a.plan) == ("a", "b")


def test_agentaction_from_dict_classmethod():
    a = AgentAction.from_dict({"message": "hi"})
    assert a.scan_text == "hi"


# --- iter_values ------------------------------------------------------------
def test_iter_values_recurses():
    vals = set(iter_values({"a": "x", "b": ["y", {"c": "z"}], "n": 5}))
    assert {"x", "y", "z", "5"} <= vals


def test_concat_text_skips_empty():
    assert concat_text("a", "", None, "b") == "a\nb"


# --- receipts ---------------------------------------------------------------
def test_canonical_json_is_order_independent():
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})


def test_receipt_hash_stable_and_64_hex():
    h = receipt_hash({"x": 1})
    assert len(h) == 64
    assert h == receipt_hash({"x": 1})


def test_receipt_hash_prefix():
    assert receipt_hash({"x": 1}, prefix="r_").startswith("r_")


def test_derive_nonce_deterministic():
    assert derive_nonce("a", "b") == derive_nonce("a", "b")
    assert derive_nonce("a", "b") != derive_nonce("a", "c")


# --- redaction --------------------------------------------------------------
def test_redact_mapping_masks_secret_keys():
    out = redact_mapping({"api_key": "sk-123", "user": "ari", "nested": {"password": "p"}})
    assert out["api_key"] == "[REDACTED]"
    assert out["user"] == "ari"
    assert out["nested"]["password"] == "[REDACTED]"


def test_apply_spans_scrubs_body():
    text = "key=AKIAIOSFODNN7EXAMPLE done"
    scrubbed = apply_spans(text, [(4, 24)])
    assert "AKIAIOSFODNN7EXAMPLE" not in scrubbed
    assert "[REDACTED]" in scrubbed


def test_apply_spans_merges_overlap():
    text = "abcdefghij"
    out = apply_spans(text, [(2, 5), (4, 7)], keep=0)
    assert out == "ab[REDACTED]hij"
