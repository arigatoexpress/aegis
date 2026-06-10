"""DomainCheck — phishing/typosquat/lookalike detection for outbound targets.

Domain-agnostic. Exact allowlist -> allow, trusted-subdomain -> review,
SequenceMatcher ratio >= threshold typosquat -> block, non-ascii host homograph
-> review, non-https -> downgrade. Pure stdlib (urllib + difflib).
"""

from __future__ import annotations

from collections.abc import Iterable
from difflib import SequenceMatcher
from urllib.parse import urlparse

from ..check import Context
from ..types import AgentAction, Check, Enforcement, Reason, Severity, enforcement_severity

__all__ = ["DomainCheck"]


def _host(target: str) -> str:
    raw = target.strip()
    if "://" not in raw:
        raw = "//" + raw  # let urlparse find the netloc
    parsed = urlparse(raw)
    host = parsed.hostname or ""
    return host.lower()


def _scheme(target: str) -> str:
    raw = target.strip()
    if "://" not in raw:
        return ""
    return urlparse(raw).scheme.lower()


class DomainCheck(Check):
    id = "domain"
    default_severity = Severity.HIGH

    def __init__(
        self,
        trusted: Iterable[str] | None = None,
        *,
        typo_threshold: float = 0.84,
        require_https: bool = True,
        enforcement: Enforcement = "block",
        block_severity: Severity | None = None,
        review_severity: Severity = Severity.MEDIUM,
    ) -> None:
        self.trusted = frozenset(d.lower().lstrip(".") for d in (trusted or ()))
        self.typo_threshold = typo_threshold
        self.require_https = require_https
        self.enforcement = enforcement
        # Fail-closed default: a typosquat, an untrusted host, or a homograph
        # lookalike BLOCKS. ``enforcement`` softens all three to review/warn in
        # one knob (so the README's "typosquat blocks" claim is true by default).
        self.block_severity = block_severity or enforcement_severity(
            enforcement, floor=Severity.HIGH
        )
        # Trusted-subdomain and non-https are genuinely softer signals and stay at
        # the (separately configurable) review severity.
        self.review_severity = review_severity

    def evaluate(self, action: AgentAction, ctx: Context) -> Iterable[Reason]:
        target = action.target
        if not target:
            return ()
        host = _host(target)
        if not host:
            return ()

        # exact allowlist -> allow (no reason emitted)
        if host in self.trusted:
            return self._scheme_reasons(target)

        reasons: list[Reason] = []

        # trusted-subdomain -> review
        sub_of = next((d for d in self.trusted if host.endswith("." + d)), None)
        if sub_of:
            reasons.append(
                Reason(
                    check_id=self.id,
                    severity=self.review_severity,
                    message=f"'{host}' is a subdomain of trusted '{sub_of}'",
                    evidence={"host": host, "rule": "subdomain", "parent": sub_of},
                )
            )
        else:
            # typosquat: fuzzy ratio against each trusted domain
            best = ("", 0.0)
            for d in self.trusted:
                ratio = SequenceMatcher(None, host, d).ratio()
                if ratio > best[1]:
                    best = (d, ratio)
            if best[1] >= self.typo_threshold and host != best[0]:
                reasons.append(
                    Reason(
                        check_id=self.id,
                        severity=self.block_severity,
                        message=f"'{host}' looks like typosquat of '{best[0]}' (ratio {best[1]:.2f})",
                        evidence={"host": host, "lookalike": best[0], "ratio": round(best[1], 3)},
                    )
                )
            elif self.trusted:
                # unknown target, not similar -> default-deny (fail closed)
                reasons.append(
                    Reason(
                        check_id=self.id,
                        severity=self.block_severity,
                        message=f"'{host}' is not in the trusted-domain set",
                        evidence={"host": host, "rule": "untrusted"},
                    )
                )

        # homograph: non-ascii host / punycode -> default-deny (fail closed)
        if any(ord(c) > 127 for c in host) or "xn--" in host:
            reasons.append(
                Reason(
                    check_id=self.id,
                    severity=self.block_severity,
                    message=f"'{host}' contains non-ascii/punycode (possible homograph)",
                    evidence={"host": host, "rule": "homograph"},
                )
            )

        reasons.extend(self._scheme_reasons(target))
        return reasons

    def _scheme_reasons(self, target: str) -> list[Reason]:
        if not self.require_https:
            return []
        scheme = _scheme(target)
        if scheme and scheme not in ("https",):
            return [
                Reason(
                    check_id=self.id,
                    severity=self.review_severity,
                    message=f"non-https scheme '{scheme}'",
                    evidence={"scheme": scheme, "rule": "scheme"},
                )
            ]
        return []
