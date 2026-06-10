"""aegis — a stdlib-only, model- and deployment-agnostic agent-safety firewall.

Wrap any AgentAction (tool call, outbound message/request, or model output) in a
Guard composed of independent, individually-usable Checks, and get back a
deterministic Decision (allowed/blocked, reasons, matched_checks, severity) plus
a tamper-evident receipt hash — with no domain, transport, or vendor presumption
in the core.

The common case needs exactly one import line::

    from aegis import Guard, Policy, AgentAction, Decision

No third-party imports exist anywhere in this package.
"""

from __future__ import annotations

# --- adapters (Protocols + stdlib defaults) ---------------------------------
from .adapters import (
    AuditSink,
    CallableNotifier,
    Clock,
    ConsoleNotifier,
    InMemoryStore,
    JsonlAuditSink,
    NoopNotifier,
    Notifier,
    NullAuditSink,
    Store,
    SystemClock,
)

# --- engine -----------------------------------------------------------------
from .check import Context, rollup, run_checks

# --- shipped checks (factories / classes, individually usable) --------------
from .checks import (
    ActionVerbCheck,
    BudgetCheck,
    CapabilityCheck,
    DomainCheck,
    ExpiryCheck,
    NonceCheck,
    OutputScanCheck,
    PiiCheck,
    PromptInjectionCheck,
    RateLimitCheck,
    SecretEgressCheck,
    SequenceCheck,
    ToolAllowlistCheck,
    default_policy,
    default_text_safety,
)

# --- eval harness -----------------------------------------------------------
from .eval import ScenarioResult, ScenarioSpec, format_matrix, run_matrix
from .guard import Guard, GuardBlocked, Policy

# --- redaction / receipts (sometimes used directly) -------------------------
from .receipt import canonical_json, receipt_hash
from .redaction import DEFAULT_SECRET_KEYS, apply_spans, redact_mapping

# --- core types -------------------------------------------------------------
from .types import (
    AgentAction,
    Check,
    Decision,
    Enforcement,
    Reason,
    Severity,
    Verdict,
    enforcement_severity,
)

__version__ = "0.1.0"

__all__ = [
    # core
    "AgentAction",
    "Decision",
    "Reason",
    "Severity",
    "Verdict",
    "Enforcement",
    "enforcement_severity",
    "Check",
    # engine
    "Guard",
    "GuardBlocked",
    "Policy",
    "Context",
    "run_checks",
    "rollup",
    # checks
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
    "default_policy",
    "default_text_safety",
    # adapters
    "Clock",
    "SystemClock",
    "Store",
    "InMemoryStore",
    "AuditSink",
    "JsonlAuditSink",
    "NullAuditSink",
    "Notifier",
    "NoopNotifier",
    "ConsoleNotifier",
    "CallableNotifier",
    # eval
    "ScenarioSpec",
    "ScenarioResult",
    "run_matrix",
    "format_matrix",
    # receipts / redaction
    "canonical_json",
    "receipt_hash",
    "redact_mapping",
    "apply_spans",
    "DEFAULT_SECRET_KEYS",
    "__version__",
]
