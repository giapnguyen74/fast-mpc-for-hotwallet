//! # chp-frost — CHP Schnorr/FROST split signing (DESIGN SP6 §4.2)
//!
//! Reference implementation of the Schnorr side of the CHP signing path.
//! Clarity over cleverness: every formula from DESIGN SP6 §4.2 appears once,
//! literally, in the module that implements it.
//!
//! | Module | DESIGN reference | Content |
//! |---|---|---|
//! | [`hash`] | SP6 §4 notation | CHP length-prefixed tagged hash, BIP340 tagged hash |
//! | [`derive`] | SP6 §4 `t_path` | `t_path = H("chp-derive-v1" ‖ key_id ‖ Y ‖ path) mod q` |
//! | [`taproot`] | SP2 Taproot note, SP6 §4.2 | `P, g_P, t_tap, Q, g_Q, g, t_eff`, BIP86 address |
//! | [`secp`] | SP6 §4.2 (Taproot) | δ-split FROST signing producing BIP340 signatures |
//! | [`ed25519`] | SP6 §4.2 (Ed25519) | δ-split FROST signing producing RFC 8032 signatures |
//! | [`dkg`] | SP2 §4 | frost-core Pedersen DKG (2-of-3) and conversion to raw scalars/points |
//!
//! Signing flow per presignature (both ciphersuites, same function names):
//!
//! 1. Presign (HOT ⇄ COLD): each side calls [`secp::presign_nonces`]
//!    (HOT: [`secp::hot_presign_nonces`]) and they exchange [`secp::Commitments`].
//! 2. Split (HOT, SP5 step 1): [`secp::split_share`]`(s_h) → (s′_h, δ)`;
//!    `s′_h` goes to PROD, `δ` to COLD.
//! 3. Both PROD and COLD build the same public [`secp::Session`] from public data.
//! 4. PROD: [`secp::prod_fragment`] → `z_h`.
//! 5. COLD: [`secp::cold_complete`] = [`secp::cold_check_fragment`] +
//!    [`secp::cold_combine`] + independent verification ([`secp::verify_bip340`]).
//!
//! The library's own Taproot tweak (`sign_with_tweak` / `aggregate_with_tweak`)
//! is deliberately **not** used: CHP adds the public tweak once, at COLD.

pub mod derive;
pub mod dkg;
pub mod ed25519;
pub mod hash;
pub mod secp;
pub mod taproot;

mod bech32m;

/// Errors from derivation and split signing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Ed25519 keys use only the root path (SP6 §4 notation).
    #[error("Ed25519 keys use only the root path \"m\"")]
    NonRootEd25519Path,
    /// A point encoding did not decode to a valid, non-identity point.
    #[error("invalid point encoding")]
    InvalidPoint,
    /// A scalar encoding was not canonical / in range.
    #[error("invalid scalar encoding")]
    InvalidScalar,
    /// A derived key (`P` or `Q`) was the point at infinity.
    #[error("derived key is the point at infinity")]
    InfinityKey,
    /// BIP341: `t = int(hashTapTweak(...))` was ≥ n.
    #[error("TapTweak hash is not below the group order")]
    TweakOutOfRange,
    /// A nonce commitment was the identity (RFC 9591 requires non-identity).
    #[error("nonce commitment is the identity")]
    IdentityCommitment,
    /// The group commitment `R` was the identity.
    #[error("group commitment R is the identity")]
    IdentityGroupCommitment,
    /// HOT and COLD identifiers must be distinct and nonzero.
    #[error("HOT and COLD identifiers must be distinct and nonzero")]
    BadIdentifiers,
    /// COLD's check of PROD's fragment against `Y′_h` failed → `FAULT_PROD_FRAGMENT`.
    #[error("FAULT_PROD_FRAGMENT: z_h does not match Y'_h")]
    FaultProdFragment,
    /// The final signature failed independent verification → `FAULT_FINAL_VERIFY`.
    #[error("FAULT_FINAL_VERIFY: final signature does not verify against Y_p")]
    FaultFinalVerify,
    /// Error surfaced by frost-core (DKG / key packages).
    #[error("frost-core: {0}")]
    Frost(String),
}
