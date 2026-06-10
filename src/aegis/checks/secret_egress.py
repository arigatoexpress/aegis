"""SecretEgressCheck — credentials/keys in text, the outbound target, or args.

Generalized off any single-vendor key shape into the broad, pluggable
SECRET_EGRESS pack. STRUCTURED key formats (AKIA, ghp_, slack xox, JWT, PEM,
Bearer, ...) are high-confidence and BLOCK; generic-entropy heuristics (bare
64-hex, long base64) are downgraded to REVIEW so a git SHA or a base64 image
data-URI doesn't hard-block legitimate output. Scans ``scan_text`` AND
``action.target`` (a key in an outbound URL/recipient must be caught) plus
recursively-walked ``args``. Emits matched fragments as redactions.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..action import iter_values, scan_targets
from ..check import Context
from ..patterns import HEURISTIC_SECRET_LABELS, SECRET_EGRESS, Pack, search_pack
from ..types import AgentAction, Check, Reason, Severity

__all__ = ["SecretEgressCheck"]


class SecretEgressCheck(Check):
    id = "secret_egress"
    default_severity = Severity.CRITICAL

    def __init__(
        self,
        pack: Pack | None = None,
        *,
        severity: Severity | None = None,
        heuristic_severity: Severity = Severity.MEDIUM,
    ) -> None:
        self.pack = pack if pack is not None else SECRET_EGRESS
        # Structured, high-confidence key formats block.
        self.default_severity = severity or Severity.CRITICAL
        # Generic-entropy heuristics (bare 64-hex / long base64) only review, to
        # avoid hard-blocking git SHAs and base64 image data-URIs.
        self.heuristic_severity = heuristic_severity

    def _severity_for(self, label: str) -> Severity:
        return self.heuristic_severity if label in HEURISTIC_SECRET_LABELS else self.default_severity

    def evaluate(self, action: AgentAction, ctx: Context) -> Iterable[Reason]:
        reasons: list[Reason] = []
        seen: set[str] = set()
        # span-scannable surfaces (text + outbound target) get offset evidence.
        for source, text in scan_targets(action):
            for label, start, end in search_pack(self.pack, text):
                frag = text[start:end]
                if frag in seen:
                    continue
                seen.add(frag)
                reasons.append(
                    Reason(
                        check_id=self.id,
                        severity=self._severity_for(label),
                        message=f"secret pattern '{label}' in {source}",
                        evidence={"label": label, "source": source, "span": [start, end]},
                        redaction=frag,
                    )
                )
        # structured arg leaves: fragment redactions (no stable offset).
        for value in iter_values(action.args):
            for label, start, end in search_pack(self.pack, value):
                frag = value[start:end]
                if frag in seen:
                    continue
                seen.add(frag)
                reasons.append(
                    Reason(
                        check_id=self.id,
                        severity=self._severity_for(label),
                        message=f"secret pattern '{label}' in args",
                        evidence={"label": label, "source": "args"},
                        redaction=frag,
                    )
                )
        return reasons
