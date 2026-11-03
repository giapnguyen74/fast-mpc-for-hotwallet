//! CHP cryptographic primitives (DESIGN SP1, SP3, SP5, SP6 §4.1).
//!
//! This crate has **no dependency on the MPC library**: PROD links it, and PROD must have no
//! code path into key generation, presign or refresh (DESIGN rule 6). Those live in `chp-mpc`.
//!
//! * [`hash`]   — length-prefixed, domain-separated hashing used for every digest in CHP.
//! * [`derive`] — CHP's public path tweak `t_path` (DESIGN SP6 §4 notation) for secp256k1.
//! * [`ident`]  — Ed25519 identity keys (enclave `id_key`) and signatures.
//! * [`seal`]   — HPKE (X25519, HKDF-SHA256, ChaCha20-Poly1305) to an enclave `wrap_pk`.
//! * [`ecdsa`]  — DKLs23 presignature halves, PROD's fragment and COLD's completion.
//! * [`verify`] — independent verifiers (libsecp256k1), separate from the MPC library.

pub mod derive;
pub mod ecdsa;
pub mod hash;
pub mod ident;
pub mod seal;
pub mod verify;

pub use k256;

/// Errors from CHP cryptographic helpers.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid encoding")]
    Encoding,
    #[error("invalid signature")]
    BadSignature,
    #[error("HPKE failure")]
    Hpke,
    #[error("invalid presignature")]
    InvalidPresign,
    #[error("final signature failed verification")]
    FinalVerify,
    #[error("MPC protocol error: {0}")]
    Mpc(String),
}
