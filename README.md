# hot-wallet-fast-mpc

Prototype and reference implementation of the **COLD-HOT-PROD protocol (CHP)**: a hot-wallet design
with multiple independent points of failure, built on threshold signatures (DKLs23 for ECDSA, FROST
for Schnorr/EdDSA).

> **Status: prototype, not for production.** This project exists to validate the design and to serve
> as a readable reference. It uses a simulated TEE/HSM, is not audited and must not hold real funds.

## The idea in brief

A hot wallet is normally a single point of failure: steal the secret or reach its API and the funds
are gone. CHP splits it into parties that an attacker must defeat separately:

| Party | Role | Holds |
|---|---|---|
| **COLD** | offline or pull-only signer; re-checks every request on its own | key share, its presignature halves |
| **HOT** | offline, powered off by default; presigns with COLD in agreed wake windows | key share |
| **PROD** | the only internet-facing party; checks requests, sends one fragment per input | HOT's one-time presignature halves only, **no key share** |
| **REC** | offline backup HSM | third key share |

- 2-of-3 threshold key from distributed key generation: the full key never exists.
- HOT → PROD only by removable media; no network link.
- Signing is one message PROD → COLD; COLD verifies the final signature before PROD broadcasts it.
- Two independent policy checks (PROD and COLD), each fed from its own sources.
- Key management happens only in quorum-opened offline ceremonies; no live path can trigger it
  (closing the TSSHOCK / BitForge class of attacks).

The full design, including ten sub-protocols (SP1–SP10), is in [`docs/DESIGN.md`](docs/DESIGN.md).

## Documents

- [`docs/DESIGN.md`](docs/DESIGN.md) — the protocol design.
- [`docs/PLAN.md`](docs/PLAN.md) — implementation plan: scope, workspace layout, phases, testing.

## Layout

Rust workspace (see [`docs/PLAN.md`](docs/PLAN.md)):

| Crate | Purpose |
|---|---|
| `chp-wire` | closed message registry, deterministic CBOR, signed frames |
| `chp-auth` | SP1: certificates, authorization matrix, 6-step frame check, quorum, revocation |
| `chp-crypto` | hashing, `t_path`, HPKE, identity keys, ECDSA fragment/completion, independent verifier (no MPC code) |
| `chp-mpc` | adapter over the vendored DKLs23 library: DKG, presign, refresh (never linked by PROD) |
| `chp-frost` | FROST δ-masked split signing, Taproot sign factors, BIP340/86/341 vectors |
| `chp-tee` | simulated TEE/HSM: keys, attestation, hardware monotonic counters |
| `chp-core` | shared engine pieces: digests, keyring, address book and proof verifier |
| `chp-chain`, `chp-policy` | EIP-1559 decoder; reference policy with per-party ledger |
| `chp-engine-hot`, `chp-engine-cold`, `chp-engine-prod` | one engine per role |
| `chp-ceremony` | enrollment, DKG ceremony, share packages, address book, REC |
| `chp-sim` | in-process simulator and end-to-end / adversarial tests |
| `thirdparty/dkls23` | vendored Silence Laboratories DKLs23 (non-commercial license, see `NOTICE`) |

## Running

```sh
cargo test --workspace            # 98 tests: crypto validation, SP1, engines, end-to-end, adversarial
./scripts/check-capabilities.sh   # PROD has no dependency path to MPC / key-management code
```

## Status

Phases 0–6 of the plan are implemented: SP1–SP7 and SP10 for ECDSA/EVM run end to end in the
simulator, including compromised-PROD, storage-restore and media-failure scenarios. FROST
cryptography is validated but not yet wired into the engines; SP8 ceremonies and SP9 QR are not
built yet. Findings about the design: [`docs/design-notes.md`](docs/design-notes.md).

## Licensing

`thirdparty/dkls23` is licensed under the Silence Laboratories **Non-Commercial** License
Agreement, which also places its non-commercial and notice terms on programs built with it. See
[`NOTICE`](NOTICE).

## Warnings

Several constructions in the design are marked **REVIEW REQUIRED** (FROST δ masking, Taproot sign
factors, CHP path derivation). They are implemented here for evaluation only and need independent
cryptographic review before any use.
