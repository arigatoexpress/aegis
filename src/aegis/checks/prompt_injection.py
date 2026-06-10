"""PromptInjectionCheck — jailbreak / instruction-override detection.

The single highest-value, most reusable check; appeared near-identically in all
three source repos. Fully generic. Upgraded from substring to word-boundary
regex, and from raw text to ``normalize_text`` (NFKC + lowercase + collapsed
whitespace + stripped zero-width/control chars) so spacing/casing/invisible-char
evasion of an injection phrase is folded away before matching.

Pattern packs are DEFENSE IN DEPTH, not a complete jailbreak classifier: they
catch known phrasings cheaply and deterministically. For semantic paraphrases the
regexes miss, layer a model-backed check by subclassing the ``Check`` ABC and
dropping it into the same ``Policy`` — aegis composes them and rolls up worst-case.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..check import Context
from ..patterns import PROMPT_INJECTION, Pack, normalize_text, search_pack
from ..types import AgentAction, Check, Reason, Severity

__all__ = ["PromptInjectionCheck"]


class PromptInjectionCheck(Check):
    id = "prompt_injection"
    default_severity = Severity.HIGH

    def __init__(self, pack: Pack | None = None, *, severity: Severity | None = None) -> None:
        self.pack = pack if pack is not None else PROMPT_INJECTION
        self.default_severity = severity or Severity.HIGH

    def evaluate(self, action: AgentAction, ctx: Context) -> Iterable[Reason]:
        # Normalize BEFORE matching: defeats "i​g​n​o​r​e", IGNORE, fullwidth, etc.
        hits = search_pack(self.pack, normalize_text(action.scan_text))
        if not hits:
            return ()
        labels = sorted({label for label, _, _ in hits})
        return (
            Reason(
                check_id=self.id,
                severity=self.default_severity,
                message=f"prompt-injection signals: {', '.join(labels)}",
                evidence={"labels": labels, "count": len(hits)},
            ),
        )
