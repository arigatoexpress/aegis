# Known limitations (v0.2 hardening backlog)

aegis v0.1.0 is **fail-closed and adversarially verified** (120 tests, 18/18 evals), but
pattern-based detection is defense-in-depth, not a guarantee. Two known gaps, found by
adversarial review and documented honestly:

1. **Intra-word-space injection evasion.** `normalize_text()` folds casing, zero-width
   chars, fullwidth, and whitespace *runs* — so `IG­NORE`, fullwidth, and `ignore   all`
   are caught. It does NOT collapse a single literal space inserted *inside* a word
   (`ig nore all previous`). The correct fix is layering an LLM-backed `Check` (the ABC
   exists for exactly this) rather than escalating regex gymnastics. v0.2: add an optional
   de-spaced scan variant guarded against false positives.
2. **URL-encoded / generic secrets in `action.target`.** Structured keys (AKIA, ghp_, JWT,
   PEM, Bearer) in an outbound URL/recipient block correctly. A *percent-encoded* token
   (`?t=ghp%5F…`, `Bearer%20…`) or a generic placeholder (`sk-…`) can slip through because
   the target isn't URL-decoded before matching. v0.2: `urllib.parse.unquote` the target
   surface in `action.scan_targets` and add a low-confidence generic-key heuristic (review).

Neither is a fail-OPEN of the *enforced* policy (allowlists/limits/grants/structured
secrets all block by default); they are coverage gaps in heuristic detection.
