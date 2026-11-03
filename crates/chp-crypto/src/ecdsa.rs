//! DKLs23 presignature halves and the online step (DESIGN SP6 §4.1).
//!
//! Presign (COLD ⇄ HOT) gives additive shares with mask `φ = φ_h + φ_c` and nonce `k`:
//!
//! ```text
//! s₁_h + s₁_c = φ·k            R = k·G,  r = R.x mod q
//! s₀′_h + s₀′_c = r·φ·x
//! ```
//!
//! CHP always presigns at the library's root path, and adds its own public path tweak `t`
//! at signing time by using `m + r·t` in place of `m` (DESIGN SP6 §4.1).

use k256::{
    elliptic_curve::{
        ops::Reduce, point::AffineCoordinates, scalar::IsHigh, sec1::ToEncodedPoint,
        subtle::ConstantTimeEq,
        PrimeField,
    },
    ProjectivePoint, Scalar, U256,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{verify::ecdsa_verify, CryptoError};

fn dec_scalar(b: &[u8; 32]) -> Result<Scalar, CryptoError> {
    Option::<Scalar>::from(Scalar::from_repr((*b).into())).ok_or(CryptoError::InvalidPresign)
}

fn dec_point(b: &[u8]) -> Result<ProjectivePoint, CryptoError> {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    let ep = k256::EncodedPoint::from_bytes(b).map_err(|_| CryptoError::Encoding)?;
    let a: Option<k256::AffinePoint> = k256::AffinePoint::from_encoded_point(&ep).into();
    a.map(ProjectivePoint::from).ok_or(CryptoError::Encoding)
}

/// Encode a point as 33-byte SEC1 compressed.
pub fn enc_point(p: &ProjectivePoint) -> [u8; 33] {
    let mut out = [0u8; 33];
    out.copy_from_slice(p.to_affine().to_encoded_point(true).as_bytes());
    out
}

/// Decode a 33-byte SEC1 compressed point.
pub fn decode_point(b: &[u8; 33]) -> Result<ProjectivePoint, CryptoError> {
    dec_point(b)
}

/// The message scalar `m` from a 32-byte prehash (same reduction as the library).
pub fn msg_scalar(m: &[u8; 32]) -> Scalar {
    Scalar::reduce(U256::from_be_slice(m))
}

/// `r = R.x mod q`.
pub fn r_scalar(big_r: &ProjectivePoint) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&big_r.to_affine().x())
}

/// One party's half of one presignature (`PreSign_h` on PROD, `PreSign_c` on COLD).
///
/// Secret material: zeroized on drop. Never `Clone` — a half is moved, never copied
/// (DESIGN rule 3, "take = delete").
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct EcdsaHalf {
    /// DKLs23 final session id (public; the "public part" in the batch digest).
    pub sid: [u8; 32],
    /// `R` (public).
    #[serde(with = "serde_bytes")]
    pub big_r: Vec<u8>,
    /// Group key `Y` the presignature was made for (public).
    #[serde(with = "serde_bytes")]
    pub y: Vec<u8>,
    phi: [u8; 32],
    s0: [u8; 32],
    s1: [u8; 32],
}

/// Redacted: never print secret values (security review).
impl std::fmt::Debug for EcdsaHalf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EcdsaHalf {{ sid: {}…, <secret redacted> }}", hex::encode(&self.sid[..4]))
    }
}

impl EcdsaHalf {
    /// Build a half from raw presign values (see `chp_mpc::half_from_presign`).
    pub fn from_parts(sid: [u8; 32], big_r: [u8; 33], y: [u8; 33], phi: [u8; 32], s0: [u8; 32], s1: [u8; 32]) -> Self {
        EcdsaHalf { sid, big_r: big_r.to_vec(), y: y.to_vec(), phi, s0, s1 }
    }

    /// **Simulation only** (`sim-hooks`): deliberately duplicate a half to model a breach or a
    /// storage snapshot. Production builds have no way to copy a half (rule 3).
    #[cfg(feature = "sim-hooks")]
    pub fn duplicate_for_test(&self) -> Self {
        EcdsaHalf {
            sid: self.sid,
            big_r: self.big_r.clone(),
            y: self.y.clone(),
            phi: self.phi,
            s0: self.s0,
            s1: self.s1,
        }
    }

    /// Well-formed: valid points, canonical scalars.
    pub fn validate(&self) -> Result<(), CryptoError> {
        self.big_r_point()?;
        self.y_point()?;
        dec_scalar(&self.phi)?;
        dec_scalar(&self.s0)?;
        dec_scalar(&self.s1)?;
        Ok(())
    }

    pub fn big_r_point(&self) -> Result<ProjectivePoint, CryptoError> {
        dec_point(&self.big_r)
    }
    pub fn y_point(&self) -> Result<ProjectivePoint, CryptoError> {
        dec_point(&self.y)
    }

    /// The public part of this presignature, hashed into the batch digest (DESIGN SP4 §4 step 4).
    pub fn public_part(&self) -> Vec<u8> {
        let mut v = self.sid.to_vec();
        v.extend_from_slice(&self.big_r);
        v
    }

    fn s0_with_message(&self, m: &Scalar, t: &Scalar) -> Result<(Scalar, Scalar), CryptoError> {
        let r = r_scalar(&self.big_r_point()?);
        let phi = dec_scalar(&self.phi)?;
        let s0 = dec_scalar(&self.s0)?;
        let s1 = dec_scalar(&self.s1)?;
        Ok(((*m + r * t) * phi + s0, s1))
    }
}

/// PROD's fragment for one input (96 bytes on the wire): `(sid, s₀_h, s₁_h)`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct EcdsaFragment {
    pub sid: [u8; 32],
    pub s0: [u8; 32],
    pub s1: [u8; 32],
}

/// PROD: `s₀_h = (m + r·t)·φ_h + s₀′_h`, plus `s₁_h`. Consumes the half (take = delete).
pub fn prod_fragment(half: EcdsaHalf, m: &[u8; 32], t: &Scalar) -> Result<EcdsaFragment, CryptoError> {
    let (s0, s1) = half.s0_with_message(&msg_scalar(m), t)?;
    Ok(EcdsaFragment { sid: half.sid, s0: s0.to_bytes().into(), s1: s1.to_bytes().into() })
    // `half` dropped (zeroized) here.
}

/// A completed, verified ECDSA signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcdsaSig {
    /// Compact `r ‖ s`, low-s.
    #[serde(with = "serde_bytes")]
    pub sig: [u8; 64],
    /// Recovery id (0..=3).
    pub recid: u8,
}

/// COLD: combine PROD's fragment with COLD's own half and **verify** against `y_p`
/// (the derived key of the job's path) with libsecp256k1. Consumes COLD's half.
///
/// Errors: `InvalidPresign` if the fragment names another session, `FinalVerify` if the
/// combined signature does not verify (DESIGN: `FAULT_PROD_FRAGMENT` / `FAULT_FINAL_VERIFY`).
pub fn cold_complete(
    cold: EcdsaHalf,
    frag: &EcdsaFragment,
    m: &[u8; 32],
    t: &Scalar,
    y_p: &ProjectivePoint,
) -> Result<EcdsaSig, CryptoError> {
    if !bool::from(frag.sid.ct_eq(&cold.sid)) {
        return Err(CryptoError::InvalidPresign);
    }
    let big_r = cold.big_r_point()?;
    let (s0_c, s1_c) = cold.s0_with_message(&msg_scalar(m), t)?;
    let s0_h = Option::<Scalar>::from(Scalar::from_repr(frag.s0.into())).ok_or(CryptoError::FinalVerify)?;
    let s1_h = Option::<Scalar>::from(Scalar::from_repr(frag.s1.into())).ok_or(CryptoError::FinalVerify)?;
    let den: Scalar = s1_h + s1_c;
    let den_inv: Scalar = Option::<Scalar>::from(den.invert()).ok_or(CryptoError::FinalVerify)?;
    let mut s = (s0_h + s0_c) * den_inv;

    let ra = big_r.to_affine();
    let r = r_scalar(&big_r);
    let mut y_odd: bool = ra.y_is_odd().into();
    let x_reduced = r.to_repr() != ra.x();
    if bool::from(s.is_high()) {
        s = -s;
        y_odd = !y_odd;
    }
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r.to_bytes());
    sig[32..].copy_from_slice(&s.to_bytes());
    ecdsa_verify(y_p, m, &sig)?;
    Ok(EcdsaSig { sig, recid: (y_odd as u8) | ((x_reduced as u8) << 1) })
}

/// **Risk demonstration (DESIGN §6):** both halves of one unused presignature give the key:
/// `x = Σs₀′ / (r·Σφ)`. Used only by tests and by the documentation of that risk.
#[cfg(feature = "sim-hooks")]
pub fn key_from_both_halves(h: &EcdsaHalf, c: &EcdsaHalf) -> Result<Scalar, CryptoError> {
    let r = r_scalar(&h.big_r_point()?);
    let num = dec_scalar(&h.s0)? + dec_scalar(&c.s0)?;
    let den = r * (dec_scalar(&h.phi)? + dec_scalar(&c.phi)?);
    let inv: Scalar = Option::<Scalar>::from(den.invert()).ok_or(CryptoError::InvalidPresign)?;
    Ok(num * inv)
}
