//! CHP path derivation for secp256k1 (DESIGN SP6 §4 notation):
//!
//! `t_path = H("chp-derive-v1" ‖ key_id ‖ Y ‖ path) mod q`, `t_path = 0` for the root path `"m"`.
//! Derived key `P = Y + t_path·G`. This is CHP's own derivation, not BIP32.
//!
//! The digest is reduced mod q (bias ≈ 2^-128, acceptable; documented in docs/design-notes.md).

use k256::{
    elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint},
    ProjectivePoint, Scalar, U256,
};

use crate::hash::tagged_hash;

pub const ROOT_PATH: &str = "m";
pub const DERIVE_TAG: &[u8] = b"chp-derive-v1";

/// Public path tweak `t_path`.
pub fn t_path(key_id: &[u8], y: &ProjectivePoint, path: &str) -> Scalar {
    if path == ROOT_PATH {
        return Scalar::ZERO;
    }
    let y_enc = y.to_affine().to_encoded_point(true);
    let d = tagged_hash(DERIVE_TAG, &[key_id, y_enc.as_bytes(), path.as_bytes()]);
    <Scalar as Reduce<U256>>::reduce_bytes(&d.into())
}

/// Derived public key `P = Y + t_path·G`.
pub fn derived_key(key_id: &[u8], y: &ProjectivePoint, path: &str) -> ProjectivePoint {
    *y + ProjectivePoint::GENERATOR * t_path(key_id, y, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::Field;

    #[test]
    fn root_path_is_identity() {
        let y = ProjectivePoint::GENERATOR * Scalar::random(&mut rand::thread_rng());
        assert_eq!(derived_key(b"k", &y, ROOT_PATH), y);
    }

    #[test]
    fn derivation_is_bound_to_key_id_y_and_path() {
        let y = ProjectivePoint::GENERATOR * Scalar::from(7u64);
        let y2 = ProjectivePoint::GENERATOR * Scalar::from(8u64);
        let a = t_path(b"key-1", &y, "m/0");
        assert_ne!(a, t_path(b"key-2", &y, "m/0"));
        assert_ne!(a, t_path(b"key-1", &y2, "m/0"));
        assert_ne!(a, t_path(b"key-1", &y, "m/1"));
        assert_eq!(a, t_path(b"key-1", &y, "m/0"));
    }

    #[test]
    fn derived_secret_matches_derived_key() {
        let x = Scalar::random(&mut rand::thread_rng());
        let y = ProjectivePoint::GENERATOR * x;
        let t = t_path(b"k", &y, "m/deposit/1");
        assert_eq!(ProjectivePoint::GENERATOR * (x + t), derived_key(b"k", &y, "m/deposit/1"));
    }
}
