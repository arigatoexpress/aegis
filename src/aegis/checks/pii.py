"""PiiCheck — email / phone / SSN / credit-card (Luhn) detection.

The gap ALL THREE source repos explicitly flagged as missing. Same regex-bank
mechanism; credit-card matches are Luhn-validated to cut false positives. Scans
``scan_text`` AND ``action.target`` (PII can ride in an outbound URL/recipient)
plus recursively-walked ``args``. Emits redaction fragments.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..action import iter_values, scan_targets
from ..check import Context
from ..patterns import PII, Pack, luhn_valid, search_pack
from ..types import AgentAction, Check, Reason, Severity

__all__ = ["PiiCheck"]


class PiiCheck(Check):
    id = "pii"
    default_severity = Severity.HIGH

    def __init__(self, pack: Pack | None = None, *, severity: Severity | None = None) -> None:
        self.pack = pack if pack is not None else PII
        self.default_severity = severity or Severity.HIGH

    def _scan(self, text: str, source: str) -> list[Reason]:
        out: list[Reason] = []
        for label, start, end in search_pack(self.pack, text):
            frag = text[start:end]
            if label == "credit_card" and not luhn_valid(frag):
                continue  # not a real card number
            out.append(
                Reason(
                    check_id=self.id,
                    severity=self.default_severity,
                    message=f"PII '{label}' in {source}",
                    evidence={"label": label, "source": source},
                    redaction=frag,
                )
            )
        return out

    def evaluate(self, action: AgentAction, ctx: Context) -> Iterable[Reason]:
        reasons: list[Reason] = []
        seen: set[str] = set()
        for source, text in scan_targets(action):
            for r in self._scan(text, source):
                if r.redaction in seen:
                    continue
                seen.add(r.redaction)
                reasons.append(r)
        for value in iter_values(action.args):
            for r in self._scan(value, "args"):
                if r.redaction in seen:
                    continue
                seen.add(r.redaction)
                reasons.append(r)
        return reasons
