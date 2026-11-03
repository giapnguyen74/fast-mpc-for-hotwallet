//! Taproot key derivation and sign factors (DESIGN SP2 Taproot note, SP6 §4.2).
//!
//! ```text
//! P     = Y + t_path·G                        derived internal key
//! g_P   = +1 if P has even y, else −1         BIP340 lift of P
//! t_tap = H_TapTweak((g_P·P).x)               BIP341 tagged hash, empty merkle root (BIP86)
//! Q     = g_P·P + t_tap·G                     BIP86 output key (Y_p = Q)
//! g_Q   = +1 if Q has even y, else −1
//! g     = g_Q·g_P                             sign on the shared secret x
//! t_eff = g_Q·(g_P·t_path + t_tap)            public part of the signing key
//! ```
//!
//! Invariant (tested): `(g·x + t_eff)·G = g_Q·Q`, the even-y lift of `Q`.
//!
//! Note `(g_P·P).x = P.x`; the x-coordinate does not depend on the lift, so
//! `t_tap = H_TapTweak(P.x)` — exactly BIP341's `taproot_tweak_pubkey(P.x, b"")`.
//! BIP341 requires failing if `t_tap ≥ n`; we return [`Error::TweakOutOfRange`]
//! (probability ≈ 2⁻¹²⁸).

use crate::derive::{sec1_compressed, t_path_secp256k1_point};
use crate::hash::bip340_tagged_hash;
use crate::Error;
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};

/// All public per-path Taproot values of SP6 §4.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaprootKey {
    /// Untweaked group key `Y` (as given).
    pub y: ProjectivePoint,
    /// `t_path` (0 for the root path).
    pub t_path: Scalar,
    /// Derived internal key `P = Y + t_path·G` (not lifted).
    pub p: ProjectivePoint,
    /// `true` iff `P` has odd y, i.e. `g_P = −1`.
    pub p_odd: bool,
    /// `t_tap = H_TapTweak(P.x)`.
    pub t_tap: Scalar,
    /// BIP86 output key `Q = g_P·P + t_tap·G` (not lifted).
    pub q: ProjectivePoint,
    /// `true` iff `Q` has odd y, i.e. `g_Q = −1`.
    pub q_odd: bool,
    /// `g_P` as a scalar (±1).
    pub g_p: Scalar,
    /// `g_Q` as a scalar (±1).
    pub g_q: Scalar,
    /// `g = g_Q·g_P` as a scalar (±1).
    pub g: Scalar,
    /// `t_eff = g_Q·(g_P·t_path + t_tap)`.
    pub t_eff: Scalar,
}

/// `+1` for even y, `−1` for odd y.
pub fn sign_factor(odd: bool) -> Scalar {
    if odd {
        -Scalar::ONE
    } else {
        Scalar::ONE
    }
}

/// `true` iff the (non-identity) point has odd y.
pub fn has_odd_y(p: &ProjectivePoint) -> bool {
    bool::from(p.to_affine().y_is_odd())
}

/// 32-byte x-coordinate of a non-identity point.
pub fn x_only(p: &ProjectivePoint) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&p.to_affine().x());
    out
}

/// BIP340 `lift_x`: the even-y point with the given x, if any.
pub fn lift_x(x: &[u8; 32]) -> Option<ProjectivePoint> {
    let mut b = [0u8; 33];
    b[0] = 0x02;
    b[1..].copy_from_slice(x);
    let ep = EncodedPoint::from_bytes(b).ok()?;
    Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep)).map(ProjectivePoint::from)
}

/// BIP341 key-path tweak with no script tree (BIP86):
/// `t = int(hash_TapTweak(P.x))`, failing if `t ≥ n`.
pub fn tap_tweak(p_x: &[u8; 32]) -> Result<Scalar, Error> {
    let h = bip340_tagged_hash("TapTweak", &[p_x]);
    Option::<Scalar>::from(Scalar::from_repr(h.into())).ok_or(Error::TweakOutOfRange)
}

impl TaprootKey {
    /// Derive all per-path values from the untweaked group key `Y` and the path.
    pub fn derive(key_id: &[u8], y: &ProjectivePoint, path: &str) -> Result<Self, Error> {
        if bool::from(y.is_identity()) {
            return Err(Error::InfinityKey);
        }
        let t_path = t_path_secp256k1_point(key_id, y, path);
        Self::from_parts(*y, t_path)
    }

    /// Values for a given internal key `P` with `t_path = 0` (used for BIP86 vectors).
    pub fn from_internal_key(p: &ProjectivePoint) -> Result<Self, Error> {
        Self::from_parts(*p, Scalar::ZERO)
    }

    fn from_parts(y: ProjectivePoint, t_path: Scalar) -> Result<Self, Error> {
        let p = y + ProjectivePoint::GENERATOR * t_path;
        if bool::from(p.is_identity()) {
            return Err(Error::InfinityKey);
        }
        let p_odd = has_odd_y(&p);
        let g_p = sign_factor(p_odd);
        let t_tap = tap_tweak(&x_only(&p))?;
        let q = p * g_p + ProjectivePoint::GENERATOR * t_tap;
        if bool::from(q.is_identity()) {
            return Err(Error::InfinityKey);
        }
        let q_odd = has_odd_y(&q);
        let g_q = sign_factor(q_odd);
        let g = g_q * g_p;
        let t_eff = g_q * (g_p * t_path + t_tap);
        Ok(Self { y, t_path, p, p_odd, t_tap, q, q_odd, g_p, g_q, g, t_eff })
    }

    /// `Y_p = Q` as the 32-byte x-only key (the witness program / BIP340 public key).
    pub fn q_xonly(&self) -> [u8; 32] {
        x_only(&self.q)
    }

    /// x-only internal key `P.x`.
    pub fn p_xonly(&self) -> [u8; 32] {
        x_only(&self.p)
    }

    /// Even-y lift of `Q` (`g_Q·Q`), the point BIP340 verification uses.
    pub fn q_even(&self) -> ProjectivePoint {
        self.q * self.g_q
    }

    /// 33-byte encoding of `g_Q·Q` (always prefix 0x02). This is the `Y_p`
    /// encoding hashed into the binding factor (see [`crate::secp`]).
    pub fn q_even_sec1(&self) -> [u8; 33] {
        sec1_compressed(&self.q_even())
    }

    /// `scriptPubKey = OP_1 OP_PUSHBYTES_32 Q.x`.
    pub fn script_pubkey(&self) -> [u8; 34] {
        let mut s = [0u8; 34];
        s[0] = 0x51;
        s[1] = 0x20;
        s[2..].copy_from_slice(&self.q_xonly());
        s
    }

    /// BIP86 / BIP350 bech32m address (`hrp` = "bc", "tb", "bcrt").
    pub fn bip86_address(&self, hrp: &str) -> String {
        crate::bech32m::segwit_v1_address(hrp, &self.q_xonly())
    }
}
