"""AgentAction construction + normalization helpers.

The generic core of all three repos' ``normalize_intent`` — alias-collapse,
recursive value extraction, and safe ``from_dict`` coercion — with no
domain-specific field assumptions.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any
from urllib.parse import unquote

from .types import AgentAction, _coerce_decimal

__all__ = ["from_dict", "iter_values", "concat_text", "scan_targets"]

# Aliases collapsed into the canonical fields. Order matters only for ``name``
# (first present wins). Everything text-ish folds into ``scan_text``.
_NAME_ALIASES = ("name", "type", "action", "tool", "method", "function")
_TEXT_ALIASES = ("scan_text", "prompt", "message", "description", "text", "content", "result")
_TARGET_ALIASES = ("target", "url", "domain", "recipient", "host", "to")
_AMOUNT_ALIASES = ("amount", "value", "cost", "price", "qty", "quantity")
_COMMITTING_ALIASES = ("committing", "requires_signature", "mutating", "write")
_DRYRUN_ALIASES = ("dry_run", "simulate", "preview")
_KNOWN = (
    set(_NAME_ALIASES)
    | set(_TEXT_ALIASES)
    | set(_TARGET_ALIASES)
    | set(_AMOUNT_ALIASES)
    | set(_COMMITTING_ALIASES)
    | set(_DRYRUN_ALIASES)
    | {"kind", "args", "plan", "meta", "params", "arguments"}
)


def _first(payload: Mapping[str, Any], aliases: tuple[str, ...]) -> Any:
    for key in aliases:
        if key in payload and payload[key] not in (None, ""):
            return payload[key]
    return None


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def iter_values(obj: Any) -> Iterator[str]:
    """Recursively yield every string leaf in a nested structure.

    Used by secret/pii checks to scan structured args, not just ``scan_text``.
    """
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, Mapping):
        for v in obj.values():
            yield from iter_values(v)
    elif isinstance(obj, (list, tuple, set)):
        for v in obj:
            yield from iter_values(v)
    elif obj is not None:
        yield str(obj)


def concat_text(*parts: Any) -> str:
    """Join non-empty text parts with newlines (the unified scan target)."""
    return "\n".join(str(p) for p in parts if p not in (None, ""))


def scan_targets(action: AgentAction) -> list[tuple[str, str]]:
    """Span-scannable free-text surfaces of an action: ``(source, text)``.

    A secret or PII value can hide in an outbound URL or recipient just as easily
    as in ``scan_text`` (e.g. ``https://evil/?token=ghp_...`` or
    ``Bearer ...@host``). Detectors that want offset-accurate redactions iterate
    THESE surfaces; structured ``args`` leaves are walked separately via
    ``iter_values`` (no stable offset into the original action).
    """
    surfaces: list[tuple[str, str]] = []
    if action.scan_text:
        surfaces.append(("text", action.scan_text))
    if action.target:
        surfaces.append(("target", action.target))
        # URL-decode target to detect percent-encoded credentials
        decoded = unquote(action.target)
        if decoded != action.target:
            surfaces.append(("target_decoded", decoded))
    return surfaces


def from_dict(payload: Mapping[str, Any]) -> AgentAction:
    """Coerce an untrusted mapping into a normalized AgentAction.

    Tolerant of common aliases; safe Decimal coercion; never raises on a missing
    or malformed field (the firewall must accept whatever the agent emits).
    """
    if not isinstance(payload, Mapping):
        raise TypeError(f"from_dict expects a mapping, got {type(payload).__name__}")

    _VALID_KINDS = ("tool_call", "message", "model_output")
    # ``kind`` may come from an explicit ``kind`` key, or from ``type`` when that
    # value is itself a valid kind (common in model output, e.g.
    # ``{"type": "message", ...}``). Otherwise ``type`` is treated as a name.
    kind_raw = payload.get("kind")
    type_is_kind = str(payload.get("type", "")) in _VALID_KINDS and "kind" not in payload
    if kind_raw is None and type_is_kind:
        kind_raw = payload["type"]
    kind = str(kind_raw) if kind_raw is not None else "tool_call"
    if kind not in _VALID_KINDS:
        kind = "tool_call"

    # If ``type`` was consumed as the kind, don't also use it as the name.
    name_aliases = tuple(a for a in _NAME_ALIASES if not (a == "type" and type_is_kind))
    name = _first(payload, name_aliases)
    target = _first(payload, _TARGET_ALIASES)
    amount = _coerce_decimal(_first(payload, _AMOUNT_ALIASES))

    # args: take an explicit args/params/arguments mapping, else everything unknown.
    raw_args = payload.get("args") or payload.get("params") or payload.get("arguments")
    if isinstance(raw_args, Mapping):
        args: dict[str, Any] = dict(raw_args)
    else:
        args = {k: v for k, v in payload.items() if k not in _KNOWN}

    # scan_text: explicit fields + any string leaves in args (so a secret hidden
    # in a tool argument still gets scanned via scan_text-only checks).
    text_parts = [payload[k] for k in _TEXT_ALIASES if k in payload and payload[k]]
    scan_text = concat_text(*text_parts)

    committing = _as_bool(_first(payload, _COMMITTING_ALIASES))
    dry_run = _as_bool(_first(payload, _DRYRUN_ALIASES))

    raw_plan = payload.get("plan") or ()
    plan = tuple(
        p if isinstance(p, AgentAction) else from_dict(p)
        for p in raw_plan
        if isinstance(p, (Mapping, AgentAction))
    )

    meta = payload.get("meta") if isinstance(payload.get("meta"), Mapping) else {}

    return AgentAction(
        kind=kind,  # type: ignore[arg-type]
        name=str(name) if name is not None else "",
        scan_text=scan_text,
        args=args,
        target=str(target) if target is not None else None,
        amount=amount,
        committing=committing,
        dry_run=dry_run,
        plan=plan,
        meta=dict(meta),
    )
