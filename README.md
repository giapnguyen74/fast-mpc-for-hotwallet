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

## Planned layout

Rust workspace (see [`docs/PLAN.md`](docs/PLAN.md) §2):

- `crates/` — wire format, identity & authorization, crypto adapters, simulated TEE, stores,
  one engine crate per role (COLD, HOT, PROD), ceremonies, address proofs, transports, simulator.
- `thirdparty/dkls23/` — vendored DKLs23 library.
- `bins/` — thin process wrappers around the engines.

## Status

Planning. Next: vendor DKLs23, create the workspace skeleton, run the phase 0 crypto spikes.

## Warnings

Several constructions in the design are marked **REVIEW REQUIRED** (FROST δ masking, Taproot sign
factors, CHP path derivation). They are implemented here for evaluation only and need independent
cryptographic review before any use.
