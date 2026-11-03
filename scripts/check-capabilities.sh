#!/usr/bin/env bash
# DESIGN rule 6 / §3 layer 2: PROD has no code path into presign, DKG, refresh or key shares.
# Fails if chp-engine-prod (or the shared crates it uses) depends on any MPC crate.
set -euo pipefail
cd "$(dirname "$0")/.."
forbidden='sl-dkls23|sl-mpc-mate|sl-oblivious|chp-mpc|chp-frost|frost-core|chp-engine-hot|chp-engine-cold|chp-ceremony'
status=0
for crate in chp-engine-prod chp-core chp-crypto chp-auth chp-wire chp-policy chp-chain; do
  if cargo tree -p "$crate" -e normal --prefix none 2>/dev/null | grep -Eq "^($forbidden) "; then
    echo "FAIL: $crate depends on MPC / key-management code:"
    cargo tree -p "$crate" -e normal --prefix none | grep -E "^($forbidden) " | sort -u
    status=1
  else
    echo "ok:   $crate has no path to MPC / key-management code"
  fi
done
exit $status
