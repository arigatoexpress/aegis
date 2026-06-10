"""Registry of the shipped checks.

Each check is a small, independently-importable, independently-constructible
class so it is usable in isolation (the 'composable' requirement)::

    from aegis.checks import PromptInjectionCheck
    from aegis.check import Context
    list(PromptInjectionCheck().evaluate(action, Context()))

``REGISTRY`` maps stable check ids -> classes for config-driven assembly.
``default_text_safety`` / ``default_policy`` are convenience bundles.
"""

from __future__ import annotations

from .allowlist import ActionVerbCheck, ToolAllowlistCheck
from .budget import BudgetCheck
from .capability import CapabilityCheck, ExpiryCheck
from .domain import DomainCheck
from .output_scan import OutputScanCheck
from .pii import PiiCheck
from .prompt_injection import PromptInjectionCheck
from .rate_limit import NonceCheck, RateLimitCheck
from .secret_egress import SecretEgressCheck
from .sequence import SequenceCheck

__all__ = [
    "PromptInjectionCheck",
    "SecretEgressCheck",
    "PiiCheck",
    "OutputScanCheck",
    "ToolAllowlistCheck",
    "ActionVerbCheck",
    "DomainCheck",
    "BudgetCheck",
    "RateLimitCheck",
    "NonceCheck",
    "CapabilityCheck",
    "ExpiryCheck",
    "SequenceCheck",
    "REGISTRY",
    "default_text_safety",
    "default_policy",
]

# Stable id -> class. Used for config-driven (JSON) assembly.
REGISTRY: dict[str, type] = {
    PromptInjectionCheck.id: PromptInjectionCheck,
    SecretEgressCheck.id: SecretEgressCheck,
    PiiCheck.id: PiiCheck,
    OutputScanCheck.id: OutputScanCheck,
    ToolAllowlistCheck.id: ToolAllowlistCheck,
    ActionVerbCheck.id: ActionVerbCheck,
    DomainCheck.id: DomainCheck,
    BudgetCheck.id: BudgetCheck,
    RateLimitCheck.id: RateLimitCheck,
    NonceCheck.id: NonceCheck,
    CapabilityCheck.id: CapabilityCheck,
    ExpiryCheck.id: ExpiryCheck,
    SequenceCheck.id: SequenceCheck,
}


def default_text_safety():
    """The always-on text-hygiene bundle (no config needed)."""
    return [PromptInjectionCheck(), SecretEgressCheck(), PiiCheck(), OutputScanCheck()]


def default_policy():
    """A sensible default check list: text safety + output scan only.

    Stateful checks (budget/rate/domain/allowlist/capability) need per-deployment
    config, so they are NOT included by default — add them explicitly.
    """
    return default_text_safety()
