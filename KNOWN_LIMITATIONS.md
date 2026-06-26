# Known limitations (v0.1.0 status)

aegis v0.1.0 is **fail-closed and adversarially verified** (28 eval scenarios, 134+ tests). The two limitations previously listed here have been resolved:

1. **Intra-word-space injection evasion** — resolved. `PromptInjectionCheck` now layers `DE_SPACED_PROMPT_INJECTION` over the de-spaced (`normalize_text` with spaces removed) surface, so `ig nore all previous` is caught.
2. **URL-encoded / generic secrets in `action.target`** — resolved. `scan_targets` now URL-decodes the target (`urllib.parse.unquote`) before matching, and the `generic_secret` heuristic triggers review-level detection for `sk-…` style tokens.

Pattern-based detection remains defense-in-depth, not a guarantee. No critical open gaps are currently known; new findings are documented here as they are discovered.
