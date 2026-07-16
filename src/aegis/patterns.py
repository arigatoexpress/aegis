"""Default signature packs as DATA (compiled regex tuples).

Patterns are data, not code, so one engine serves any domain by swapping
wordlists. Loadable/overridable from JSON via ``load_pack``. The defaults carry
no domain-specific vocabulary.

Each pack entry is ``(label, compiled_regex)``. Checks OR-search the pack.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Iterable, Mapping
from pathlib import Path

__all__ = [
    "Pattern",
    "Pack",
    "PROMPT_INJECTION",
    "DE_SPACED_PROMPT_INJECTION",
    "SECRET_EGRESS",
    "PII",
    "HEURISTIC_SECRET_LABELS",
    "compile_pack",
    "load_pack",
    "search_pack",
    "normalize_text",
    "luhn_valid",
]

Pattern = tuple[str, "re.Pattern[str]"]
Pack = tuple[Pattern, ...]

_FLAGS = re.IGNORECASE

# Generic-entropy heuristics (vs. structured key formats). These match plenty of
# benign strings — a git SHA is bare 64-hex, an inline image is long base64 — so
# SecretEgressCheck downgrades them to REVIEW instead of a hard BLOCK.
HEURISTIC_SECRET_LABELS: frozenset[str] = frozenset({"high_entropy_hex", "base64_blob", "generic_secret"})

# Zero-width / invisible chars an attacker can splatter through "i​g​n​o​r​e"
# to dodge a literal-substring matcher. Stripped during normalization.
_ZERO_WIDTH = dict.fromkeys(
    map(ord, "​‌‍‎‏⁠﻿­͏؜"), None
)
_WS_RUN = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    """Fold an attacker's evasion tricks before pattern matching.

    NFKC (collapses fullwidth/compatibility lookalikes) -> drop zero-width and
    control chars -> lowercase -> collapse whitespace runs to single spaces. This
    defeats spacing/casing/invisible-char obfuscation of injection phrases while
    leaving normal prose semantically intact.
    """
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_ZERO_WIDTH)
    # strip control chars (category Cc/Cf) except keep word/space separators sane
    text = "".join(ch for ch in text if unicodedata.category(ch) not in ("Cc", "Cf"))
    text = text.lower()
    text = _WS_RUN.sub(" ", text)
    return text.strip()


def compile_pack(spec: Iterable[tuple[str, str]]) -> Pack:
    """Compile a sequence of ``(label, regex_str)`` into a Pack."""
    return tuple((label, re.compile(rx, _FLAGS)) for label, rx in spec)


def load_pack(source: str | Path | Mapping[str, str]) -> Pack:
    """Load a pack from a JSON file/string or a ``{label: regex}`` mapping.

    JSON shape: ``{"label": "regex", ...}``. Lets an operator swap detection
    wordlists without touching code.
    """
    if isinstance(source, Mapping):
        data = dict(source)
    else:
        text = Path(source).read_text() if Path(str(source)).exists() else str(source)
        data = json.loads(text)
    return compile_pack((label, rx) for label, rx in data.items())


def search_pack(pack: Pack, text: str) -> list[tuple[str, int, int]]:
    """Return ``(label, start, end)`` for every match of every pattern."""
    hits: list[tuple[str, int, int]] = []
    if not text:
        return hits
    for label, rx in pack:
        for m in rx.finditer(text):
            hits.append((label, m.start(), m.end()))
    return hits


def luhn_valid(number: str) -> bool:
    """Luhn checksum for credit-card validation. Digits-only input expected."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# --- PROMPT INJECTION -------------------------------------------------------
# Word-boundary regex upgraded from the substring matching in the source repos.
# NOTE: scanned over ``normalize_text`` output (NFKC + lowercased + whitespace-
# collapsed + zero-width-stripped), so spacing/casing/invisible-char evasion is
# already folded away before these patterns run. Pattern packs are
# defense-in-depth, not a complete jailbreak classifier — layer an LLM-based
# check via the ``Check`` ABC for semantic paraphrases these regexes miss.
PROMPT_INJECTION: Pack = compile_pack(
    [
        ("ignore_previous", r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b"),
        ("disregard", r"\bdisregard\s+(?:all\s+|everything\s+)?(?:previous|prior|above|the)\b"),
        ("forget", r"\bforget\s+(?:all\s+|everything\s+)?(?:above|previous|prior|what|that|you\s+were\s+told)\b"),
        ("new_instructions", r"\bnew\s+instructions?\s*:"),
        ("override_guard", r"\b(?:bypass|disable|turn\s+off|override)\s+(?:the\s+)?(?:guard|policy|safety|filter|rules?)\b"),
        ("new_mode", r"\byou\s+are\s+now\s+(?:in\s+)?\w+\s+mode\b"),
        ("you_are_now", r"\byou\s+are\s+now\b"),
        ("dan", r"\bDAN\b|\bdo\s+anything\s+now\b"),
        ("system_prompt", r"\b(?:system\s+prompt|developer\s+message|system\s+message)\b"),
        ("reveal_instructions", r"\b(?:reveal|print|show|repeat|output)\s+(?:your\s+)?(?:system\s+prompt|instructions|prompt)\b"),
        ("no_logging", r"\b(?:do\s+not|don't|never)\s+(?:log|record|tell|report|mention)\b"),
        ("secretly", r"\bsecretly\b"),
        ("without_approval", r"\bwithout\s+(?:the\s+)?(?:user'?s?\s+)?(?:approval|consent|permission|confirmation)\b"),
        ("exfiltrate", r"\b(?:exfiltrate|leak|send\s+me|email\s+me|print)\s+(?:the\s+)?(?:secret|secrets|credentials?|password|api\s*key)\b"),
        ("pretend", r"\bpretend\s+(?:you\s+are|to\s+be)\b"),
        ("jailbreak", r"\bjailbreak\b"),
        ("act_as", r"\bact\s+as\s+(?:if\s+)?(?:you\s+have\s+no|an\s+unrestricted|a\s+dev)\b"),
    ]
)

DE_SPACED_PROMPT_INJECTION: Pack = compile_pack(
    [
        ("ignore_previous", r"ignore(?:all)?(?:previous|prior|above)instructions?"),
        ("disregard", r"disregard(?:all|everything)?(?:previous|prior|above|the)"),
        ("forget", r"forget(?:all|everything)?(?:above|previous|prior|what|that|youweretold)"),
        ("new_instructions", r"newinstructions?"),
        ("override_guard", r"(?:bypass|disable|turnoff|override)(?:the)?(?:guard|policy|safety|filter|rules?)"),
        ("new_mode", r"youarenow(?:in)?\w+mode"),
        ("you_are_now", r"youarenow"),
        ("dan", r"doanythingnow"),
        ("system_prompt", r"(?:systemprompt|developermessage|systemmessage)"),
        ("reveal_instructions", r"(?:reveal|print|show|repeat|output)(?:your)?(?:systemprompt|instructions|prompt)"),
        ("no_logging", r"(?:donot|dont|never)(?:log|record|tell|report|mention)"),
        ("without_approval", r"without(?:the)?(?:user'?s?)?(?:approval|consent|permission|confirmation)"),
        ("exfiltrate", r"(?:exfiltrate|leak|sendme|emailme|print)(?:the)?(?:secret|secrets|credentials?|password|apikey)"),
        ("pretend", r"pretend(?:youare|tobe)"),
        ("act_as", r"actas(?:if)?(?:youhaveno|anunrestricted|adev)"),
    ]
)

# --- SECRET / CREDENTIAL EGRESS --------------------------------------------
# Generalized off any single-vendor key shape into a broad, pluggable set.
SECRET_EGRESS: Pack = compile_pack(
    [
        ("aws_access_key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        ("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        ("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        ("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
        ("pem_block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
        ("bearer", r"\bBearer\s+[A-Za-z0-9_\-\.=]{16,}\b"),
        ("private_key_phrase", r"\b(?:private[\s_-]?key|secret[\s_-]?key)\b\s*[:=]"),
        ("recovery_phrase", r"\b(?:recovery\s+(?:phrase|code|key)|backup\s+codes?)\b"),
        ("api_key_phrase", r"\b(?:api[\s_-]?key|access[\s_-]?token|client[\s_-]?secret)\b\s*[:=]"),
        ("password_assign", r"\bpassword\b\s*[:=]\s*\S{6,}"),
        ("generic_secret", r"\b(?:sk|key|secret|token)[_\-:][A-Za-z0-9_\-]{12,}\b"),
        ("high_entropy_hex", r"\b[0-9a-fA-F]{64}\b"),
        ("base64_blob", r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
    ]
)

# --- PII --------------------------------------------------------------------
# The gap ALL THREE source repos explicitly flagged as missing.
PII: Pack = compile_pack(
    [
        ("email", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        ("phone_us", r"(?<!\d)(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\d)"),
        ("ssn", r"\b(?!000|666|9\d\d)\d{3}[\s.\-]?(?!00)\d{2}[\s.\-]?(?!0000)\d{4}\b"),
        ("credit_card", r"\b(?:\d[ \-]?){13,19}\b"),
    ]
)
