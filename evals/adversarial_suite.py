"""Adversarial golden-eval suite (repo entrypoint).

The suite itself now lives in the installed package (``aegis.adversarial``) so the
``aegis-evals`` console script resolves from ANY working directory — the old
top-level ``evals`` module only imported when cwd happened to be the repo root.

This file stays as the repo's pytest-collected spec and a runnable script. It
re-exports the package suite so ``evals/`` remains "the spec" per the charter
without duplicating the scenario table.
"""

from __future__ import annotations

import sys

from aegis.adversarial import SPECS, build_guard, main, run

__all__ = ["SPECS", "build_guard", "main", "run", "test_adversarial_matrix"]


# --- pytest integration: every spec is also a unit test ---------------------
def test_adversarial_matrix():
    results, ok = run()
    failures = [r.spec.id for r in results if not r.passed]
    assert ok, f"failing scenarios: {failures}"


if __name__ == "__main__":
    sys.exit(main())
