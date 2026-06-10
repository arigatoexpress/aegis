# AGENTS.md — aegis Charter

## What this is
`aegis` — a stdlib-only agent-safety firewall: wrap any agent action (tool call,
outbound message, or model output) in a Guard of composable Checks and get back a
deterministic Decision plus a tamper-evident receipt. No vendor, domain, or
platform assumption anywhere in core.

## Operating principles (non-negotiable)
1. **Composable** — every Check is a class usable in isolation
   (`list(check.evaluate(action, ctx))`); Policies compose with `+` and subset
   with `.only`/`.without`; the Guard only orchestrates. No god-objects, no hidden
   global state.
2. **Model-agnostic** — the firewall never calls an LLM. It evaluates an
   `AgentAction` you build from any model's output. Zero LLM SDK in the tree.
3. **Deployment-agnostic** — runs as a plain process AND in Docker with zero code
   change. Core makes no outbound calls; persistence/notification/clock are
   injected adapters with stdlib defaults.
4. **Evals are the spec** — `evals/adversarial_suite.py` is the behavioral
   contract. Tests + evals green before merge.
5. **Simplicity first** — stdlib only (`re, hashlib, json, decimal, difflib,
   urllib, collections, datetime`). Delete > add.
6. **Surgical diffs** — one concern per PR/commit.

## Layout
- `src/aegis/` — pure library. `types.py` (subject/verdict/Check ABC),
  `check.py` + `guard.py`/`engine.py` (the engine), `checks/` (one shipped check
  per module), `patterns.py` (detection packs as DATA), `adapters/` (the
  outside-world boundary as Protocols + stdlib defaults), `eval.py` (golden-eval
  harness).
- `tests/` — table-driven unit tests, positive + negative per check.
- `evals/` — adversarial golden specs (the executable spec).
- `examples/quickstart.py` — proves the model- and deployment-agnostic claims.

## Boundaries
- **Adapter boundary is sacred.** Anything touching the outside world (clock,
  store, audit, notifier) is reached only through a Protocol in
  `adapters/__init__.py`. A check never imports a concretion. Adding a Redis store
  or Slack notifier never touches a single check.
- **Patterns are data.** Detection lives in regex packs (`patterns.py`),
  loadable from JSON. Swapping wordlists serves a new domain without code changes.
- **Fail-closed.** A check that raises becomes a CRITICAL Reason; it never
  fails-open.
- **No domain-specific vocabulary** in core, by construction. Any
  domain-coupled checks that were stripped are re-addable as user `Check`
  subclasses — nothing lost, nothing presumed.
- No outward side effects (email/deploy/money) reachable from core.
