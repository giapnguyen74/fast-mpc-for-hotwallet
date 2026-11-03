# Third-party patches

## `thirdparty/dkls23` — Silence Laboratories `sl-dkls23` 1.0.1-beta (crates.io)

Vendored from `https://static.crates.io/crates/sl-dkls23/sl-dkls23-1.0.1-beta.crate`.
Full diff: [`thirdparty/dkls23-chp.patch`](../thirdparty/dkls23-chp.patch).

| # | File | Change | Why |
|---|---|---|---|
| 1 | `src/sign/messages.rs` | read-only accessors `PreSign::chp_s0/chp_s1/chp_phi/chp_big_r/chp_public_key/chp_party_id` | CHP computes the online fragment itself with the path tweak `m + r·t` (DESIGN SP6 §4.1). The struct is already `repr(C)` + `AnyBitPattern`, so nothing new is exposed |
| 2 | `Cargo.toml` | pin `sl-mpc-mate = "=1.0.0-beta"` | `^1.0.0-beta` resolves to 1.1.x, whose API (`coord`, `message` modules) is incompatible |

Usage notes (see `crates/chp-crypto/src/dkls.rs`):

- CHP always presigns at the library root path `m` and applies its own derivation `t_path` at signing.
- Library message signing is disabled (`NoSigningKey`); every library message travels inside a
  CHP `SignedMsg` checked before the bytes reach the library.
- Fixed party ids: HOT = 0, COLD = 1, REC = 2.
