"""AuditSink protocol + stdlib defaults.

Replaces the source repos' external anchoring with a generic,
deployment-agnostic sink. The default writes an append-only JSONL line; a
Postgres/S3/anchoring sink is a user-supplied adapter implementing ``write``.
Secrets are redacted before the record is persisted.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from ..receipt import canonical_json

if TYPE_CHECKING:  # pragma: no cover
    from ..types import Decision

__all__ = ["AuditSink", "NullAuditSink", "JsonlAuditSink"]


@runtime_checkable
class AuditSink(Protocol):
    """Persist a decision record. Append-only, deployment-agnostic."""

    def write(self, decision: Decision) -> None: ...


class NullAuditSink:
    """Default: persists nothing."""

    def write(self, decision: Decision) -> None:
        return None


class JsonlAuditSink:
    """Append one canonical-JSON line per decision to a file.

    The line is ``decision.to_dict()`` — already redaction-clean by the time the
    Guard hands it over.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def write(self, decision: Decision) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(canonical_json(decision.to_dict()) + "\n")
