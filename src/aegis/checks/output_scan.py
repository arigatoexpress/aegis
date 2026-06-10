"""OutputScanCheck — never echo sensitive content back.

Runs the secret + pii + injection packs over MODEL OUTPUT / tool-result text
(``kind == 'model_output'``) and accumulates a deduped redactions list. Records
what to strip; pairs with ``redaction.apply_spans`` / ``redaction.redact_text``
to actually scrub.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..action import scan_targets
from ..check import Context
from ..patterns import (
    HEURISTIC_SECRET_LABELS,
    PII,
    PROMPT_INJECTION,
    SECRET_EGRESS,
    Pack,
    luhn_valid,
    normalize_text,
    search_pack,
)
from ..types import AgentAction, Check, Reason, Severity

__all__ = ["OutputScanCheck"]


class OutputScanCheck(Check):
    id = "output_scan"
    default_severity = Severity.HIGH

    def __init__(
        self,
        *,
        secret_pack: Pack | None = None,
        pii_pack: Pack | None = None,
        injection_pack: Pack | None = None,
        only_model_output: bool = True,
        secret_severity: Severity = Severity.CRITICAL,
        heuristic_secret_severity: Severity = Severity.MEDIUM,
    ) -> None:
        self.secret_pack = secret_pack if secret_pack is not None else SECRET_EGRESS
        self.pii_pack = pii_pack if pii_pack is not None else PII
        self.injection_pack = injection_pack if injection_pack is not None else PROMPT_INJECTION
        self.only_model_output = only_model_output
        # Structured keys block; generic-entropy heuristics only review (so a git
        # SHA / base64 image data-URI echoed in output doesn't hard-block).
        self.secret_severity = secret_severity
        self.heuristic_secret_severity = heuristic_secret_severity

    def evaluate(self, action: AgentAction, ctx: Context) -> Iterable[Reason]:
        if self.only_model_output and action.kind != "model_output":
            return ()
        reasons: list[Reason] = []
        seen: set[str] = set()

        def emit(frag: str, label: str, span: tuple[int, int], sev: Severity, kind: str, source: str) -> None:
            if frag in seen:
                return
            seen.add(frag)
            reasons.append(
                Reason(
                    check_id=self.id,
                    severity=sev,
                    message=f"{kind} '{label}' echoed in {source}",
                    evidence={"label": label, "kind": kind, "span": list(span), "source": source},
                    redaction=frag,
                )
            )

        # secrets + pii: scan raw surfaces (text + outbound target) so redaction
        # offsets/fragments are exact (never lowercase a secret).
        for source, text in scan_targets(action):
            for label, s, e in search_pack(self.secret_pack, text):
                sev = self.heuristic_secret_severity if label in HEURISTIC_SECRET_LABELS else self.secret_severity
                emit(text[s:e], label, (s, e), sev, "secret", source)
            for label, s, e in search_pack(self.pii_pack, text):
                if label == "credit_card" and not luhn_valid(text[s:e]):
                    continue
                emit(text[s:e], label, (s, e), Severity.HIGH, "pii", source)

        # injection: scan NORMALIZED text (folds evasion); no secret to scrub, so
        # the fragment is just the normalized signal.
        norm = normalize_text(action.scan_text)
        for label, s, e in search_pack(self.injection_pack, norm):
            emit(norm[s:e], label, (s, e), Severity.MEDIUM, "injection", "text")
        return reasons
