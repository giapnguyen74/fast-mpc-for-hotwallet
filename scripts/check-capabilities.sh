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
# Simulation hooks (copy halves, restore storage, forge jobs) must never be compiled into a
# production build. Checked on the RESOLVED feature set of normal (non-dev) builds, both per
# engine and for the whole workspace, failing closed on any cargo error (security review r2).
hooked=(chp-engine-prod chp-engine-cold chp-engine-hot chp-crypto)
check_tree() { # $1 = description, rest = cargo tree args
  local what="$1"; shift
  local out
  if ! out=$(cargo tree "$@" -e normal,features --prefix none -f '{p} [{f}]' 2>&1); then
    echo "FAIL: cargo tree failed for $what"; echo "$out" | tail -3; status=1; return
  fi
  for c in "${hooked[@]}"; do
    if echo "$out" | grep -E "^$c v[^ ]+ .*\[[^]]*sim-hooks" >/dev/null; then
      echo "FAIL: $c is built with feature sim-hooks in $what"; status=1
    fi
  done
}
for crate in "${hooked[@]}"; do
  check_tree "$crate" -p "$crate"
done
check_tree "the workspace build" --workspace
[ $status -eq 0 ] && echo "ok:   no production build (per engine or workspace) compiles sim-hooks"
exit $status
