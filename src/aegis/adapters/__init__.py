"""Adapter protocols + stdlib defaults — the boundary that keeps the outside
world OUT of core.

Core depends only on these narrow Protocols (Clock, Store, AuditSink, Notifier,
SignaturePackLoader), never concretions. Every Protocol ships a stdlib default
so the library runs with zero configuration and zero outbound calls. A Redis
store, a Slack notifier, an HTTP server, or a database audit sink are all
user-supplied adapters or live in an optional extras package core never imports.
"""

from __future__ import annotations

from .audit import AuditSink, JsonlAuditSink, NullAuditSink
from .notifier import CallableNotifier, ConsoleNotifier, NoopNotifier, Notifier
from .store import Clock, InMemoryStore, Store, SystemClock

__all__ = [
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
]
