#!/usr/bin/env bash
# Self-audit: fail if any domain-specific (crypto/chain/wallet/vendor) vocabulary
# leaked into the source. Auth-token terms (access_token, refresh_token, JWT,
# bearer, client_secret) are legitimate secret-egress detection vocabulary and
# are allowlisted out. Run from the repo root.
set -euo pipefail

PATTERN='chain|crypto|wallet|web3|megaeth|robinhood|hyperliquid|ethereum|solana|metamask|blockchain|on-?chain|erc-?[0-9]|calldata|\brpc\b|\bsui\b|\beth\b|\b0g\b'
ALLOW='access_token|refresh_token|client_secret|bearer|\bjwt\b'

# Scan only hand-written package source (skip binaries + generated metadata).
hits=$(grep -rniE --include='*.py' "$PATTERN" src/ 2>/dev/null | grep -viE "$ALLOW" || true)

if [ -n "$hits" ]; then
  echo "FAIL: domain-specific vocabulary found in src/:"
  echo "$hits"
  exit 1
fi
echo "clean: no domain-specific vocabulary in src/"
