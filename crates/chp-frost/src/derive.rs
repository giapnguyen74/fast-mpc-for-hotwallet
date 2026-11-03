//! CHP path derivation (DESIGN SP6 §4 notation, `t_path`).
//!
//! ```text
//! t_path = H("chp-derive-v1" ‖ key_id ‖ Y ‖ path) mod q        (t_path = 0 for path "m")
//! P      = Y + t_path·G
//! ```
//!
//! Inputs, exactly as hashed (each field length-prefixed by [`crate::hash`] framing):
//!
//! | field | encoding |
//! |---|---|
//! | tag | `b"chp-derive-v1"` |
//! | `key_id` | raw bytes as given |
//! | `Y` | secp256k1: 33-byte compressed SEC1; Ed25519: 32-byte RFC 8032 encoding |
//! | `path` | UTF-8 bytes of the path string (e.g. `"m/0/7"`) |
//!
//! Reduction:
//! - **secp256k1**: SHA-256 framing, the 32-byte digest read big-endian and reduced
//!   mod n. (Bias ≈ 2⁻¹²⁸, since n is within 2¹²⁹ of 2²⁵⁶ — acceptable, same as BIP340.)
//! - **Ed25519**: SHA-512 framing ([`crate::hash::tagged_hash_512`]), the 64-byte
//!   digest reduced mod ℓ with `Scalar::from_bytes_mod_order_wide` (a 32-byte
//!   digest mod ℓ ≈ 2²⁵² would be biased). Ed25519 keys only use the root path,
//!   so this function returns 0 in practice; the non-root branch exists so that
//!   the convention is pinned down if that ever changes.
//!
//! The root path is the exact string `"m"`; any other string, including `"m/"`,
//! is a non-root path.

use crate::hash::{tagged_hash, tagged_hash_512};
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;

/// Domain-separation tag for `t_path`.
pub const DERIVE_TAG: &[u8] = b"chp-derive-v1";
/// The root path; `t_path("m") = 0`.
pub const ROOT_PATH: &str = "m";

/// `t_path` for a secp256k1 group key given as 33-byte compressed SEC1.
pub fn t_path_secp256k1(key_id: &[u8], y_sec1: &[u8; 33], path: &str) -> k256::Scalar {
    if path == ROOT_PATH {
        return k256::Scalar::ZERO;
    }
    let digest = tagged_hash(DERIVE_TAG, &[key_id, y_sec1, path.as_bytes()]);
    <k256::Scalar as Reduce<k256::U256>>::reduce_bytes(&digest.into())
}

/// `t_path` for a secp256k1 group key given as a point (encoded compressed).
pub fn t_path_secp256k1_point(key_id: &[u8], y: &k256::ProjectivePoint, path: &str) -> k256::Scalar {
    t_path_secp256k1(key_id, &sec1_compressed(y), path)
}

/// `t_path` for an Ed25519 group key given as its 32-byte encoding.
pub fn t_path_ed25519(key_id: &[u8], y: &[u8; 32], path: &str) -> curve25519_dalek::Scalar {
    if path == ROOT_PATH {
        return curve25519_dalek::Scalar::ZERO;
    }
    let digest = tagged_hash_512(DERIVE_TAG, &[key_id, y, path.as_bytes()]);
    curve25519_dalek::Scalar::from_bytes_mod_order_wide(&digest)
}

/// 33-byte compressed SEC1 encoding of a non-identity secp256k1 point.
///
/// Panics on the identity (which has no 33-byte encoding); callers only pass
/// group keys and derived keys, which are checked to be non-identity.
pub fn sec1_compressed(p: &k256::ProjectivePoint) -> [u8; 33] {
    let enc = p.to_affine().to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(enc.as_bytes());
    out
}
