//! δ-split FROST signing for Ed25519 (RFC 9591 FROST(Ed25519, SHA-512)), DESIGN SP6 §4.2.
//!
//! Ed25519 keys use the root path only, so `Y_p = Y`, `g = 1`, `t_eff = 0`, `g_R = 1`.
//! The formulas are those of [`crate::secp`] with those values substituted:
//!
//! ```text
//! ρ_j = H1( ser(Y) ‖ H4(m) ‖ H5(encode_group_commitment_list(B)) ‖ ser(i_j) )
//! R   = Σ_j (D_j + ρ_j·E_j)
//! c   = H2( ser(R) ‖ ser(Y) ‖ m )                             (= RFC 8032 challenge)
//! PROD:  z_h = d_h + e_h·ρ_h + λ_h·s′_h·c
//! COLD:  z_h·G == D_h + ρ_h·E_h + λ_h·c·Y′_h,  Y′_h = Y_h + δ·G
//!        z_c  = d_c + e_c·ρ_c + λ_c·s′_c·c,    s′_c = s_c + (i_c/i_h)·δ
//!        z    = z_h + z_c,  signature = ser(R) ‖ ser(z)
//! ```
//!
//! Exactly what is hashed (context string `"FROST-ED25519-SHA512-v1"`, matching
//! frost-ed25519 3.0 byte for byte — tested):
//! - `ser(point)` = 32-byte RFC 8032 encoding; `ser(i)` = 32-byte little-endian scalar.
//! - `H1(x) = SHA-512(ctx ‖ "rho" ‖ x) mod ℓ` (64-byte wide reduction).
//! - `H2(x) = SHA-512(x) mod ℓ` (no context string, for RFC 8032 compatibility).
//! - `H4(x) = SHA-512(ctx ‖ "msg" ‖ x)`, `H5(x) = SHA-512(ctx ‖ "com" ‖ x)` (64 bytes).
//! - commitment list sorted by identifier as an integer.

use crate::derive::{t_path_ed25519, ROOT_PATH};
use crate::Error;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

/// RFC 9591 context string of FROST(Ed25519, SHA-512).
pub const CONTEXT_STRING: &[u8] = b"FROST-ED25519-SHA512-v1";

/// Ed25519 group key for signing. Only the root path exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ed25519Key {
    /// `Y_p = Y`.
    pub y: EdwardsPoint,
}

impl Ed25519Key {
    /// `Y_p` for a path; only `"m"` is accepted (`t_path = 0`).
    pub fn derive(key_id: &[u8], y: &EdwardsPoint, path: &str) -> Result<Self, Error> {
        if path != ROOT_PATH {
            return Err(Error::NonRootEd25519Path);
        }
        if y.is_identity() || y.is_small_order() {
            return Err(Error::InvalidPoint);
        }
        // t_path is 0 by definition for the root; computed for uniformity.
        let t = t_path_ed25519(key_id, &y.compress().to_bytes(), path);
        debug_assert_eq!(t, Scalar::ZERO);
        Ok(Self { y: *y })
    }
    /// 32-byte encoding of `Y_p`.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.y.compress().to_bytes()
    }
}

/// Decode a 32-byte point encoding (rejecting identity).
pub fn decode_point(b: &[u8; 32]) -> Result<EdwardsPoint, Error> {
    let p = CompressedEdwardsY(*b).decompress().ok_or(Error::InvalidPoint)?;
    if p.is_identity() {
        return Err(Error::InvalidPoint);
    }
    Ok(p)
}

/// Decode a canonical 32-byte little-endian scalar.
pub fn decode_scalar(b: &[u8; 32]) -> Result<Scalar, Error> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*b)).ok_or(Error::InvalidScalar)
}

// ---------------------------------------------------------------------------
// Nonces
// ---------------------------------------------------------------------------

/// One side's secret nonce pair `(d, e)`. Not `Clone`: consumed by one signing call.
#[derive(Debug)]
pub struct SecretNonces {
    d: Scalar,
    e: Scalar,
}

/// Public commitments `(D, E)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitments {
    /// `D = d·G`
    pub hiding: EdwardsPoint,
    /// `E = e·G`
    pub binding: EdwardsPoint,
}

impl SecretNonces {
    /// Rebuild from stored scalars. Both must be nonzero.
    pub fn from_scalars(d: Scalar, e: Scalar) -> Result<Self, Error> {
        if d == Scalar::ZERO || e == Scalar::ZERO {
            return Err(Error::InvalidScalar);
        }
        Ok(Self { d, e })
    }
    /// The stored scalars (secret).
    pub fn to_scalars(&self) -> (Scalar, Scalar) {
        (self.d, self.e)
    }
    /// `(d·G, e·G)`.
    pub fn commitments(&self) -> Commitments {
        Commitments {
            hiding: EdwardsPoint::mul_base(&self.d),
            binding: EdwardsPoint::mul_base(&self.e),
        }
    }
}

/// Uniform random nonzero scalar (64 random bytes, wide reduction).
pub fn random_nonzero<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    loop {
        let mut b = [0u8; 64];
        rng.fill_bytes(&mut b);
        let s = Scalar::from_bytes_mod_order_wide(&b);
        if s != Scalar::ZERO {
            return s;
        }
    }
}

/// Generate one nonce pair and its commitments (presign). Used by both sides.
pub fn presign_nonces<R: RngCore + CryptoRng>(rng: &mut R) -> (SecretNonces, Commitments) {
    let n = SecretNonces { d: random_nonzero(rng), e: random_nonzero(rng) };
    let c = n.commitments();
    (n, c)
}

/// HOT's presign nonce generation (alias of [`presign_nonces`]).
pub fn hot_presign_nonces<R: RngCore + CryptoRng>(rng: &mut R) -> (SecretNonces, Commitments) {
    presign_nonces(rng)
}

// ---------------------------------------------------------------------------
// Signer set, δ split
// ---------------------------------------------------------------------------

/// FROST identifier scalars `{i_h, i_c}` (see [`crate::secp::SignerIds`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignerIds {
    /// `i_h`
    pub hot: Scalar,
    /// `i_c`
    pub cold: Scalar,
}

impl SignerIds {
    /// Validates `i_h ≠ i_c`, both nonzero.
    pub fn new(hot: Scalar, cold: Scalar) -> Result<Self, Error> {
        if hot == Scalar::ZERO || cold == Scalar::ZERO || hot == cold {
            return Err(Error::BadIdentifiers);
        }
        Ok(Self { hot, cold })
    }
    /// `λ_h = i_c/(i_c − i_h)`.
    pub fn lambda_hot(&self) -> Scalar {
        self.cold * (self.cold - self.hot).invert()
    }
    /// `λ_c = i_h/(i_h − i_c)`.
    pub fn lambda_cold(&self) -> Scalar {
        self.hot * (self.hot - self.cold).invert()
    }
    /// `i_c/i_h`.
    pub fn mask_ratio(&self) -> Scalar {
        self.cold * self.hot.invert()
    }
}

/// HOT: `(s′_h, δ) = (s_h + δ, δ)` with fresh random nonzero `δ`.
pub fn split_share<R: RngCore + CryptoRng>(s_h: &Scalar, rng: &mut R) -> (Scalar, Scalar) {
    let delta = random_nonzero(rng);
    (s_h + delta, delta)
}

/// COLD: `s′_c = s_c + (i_c/i_h)·δ`.
pub fn cold_masked_share(s_c: &Scalar, delta: &Scalar, ids: &SignerIds) -> Scalar {
    s_c + ids.mask_ratio() * delta
}

/// COLD: `Y′_h = Y_h + δ·G`.
pub fn masked_verifying_share(y_h: &EdwardsPoint, delta: &Scalar) -> EdwardsPoint {
    y_h + EdwardsPoint::mul_base(delta)
}

// ---------------------------------------------------------------------------
// Hashes
// ---------------------------------------------------------------------------

fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// RFC 8032 / RFC 9591 H2 challenge `c = SHA-512(R ‖ Y ‖ m) mod ℓ`.
pub fn challenge(r: &EdwardsPoint, y: &EdwardsPoint, msg: &[u8]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&sha512(&[
        &r.compress().to_bytes(),
        &y.compress().to_bytes(),
        msg,
    ]))
}

/// RFC 9591 binding factors `(ρ_h, ρ_c)`.
pub fn binding_factors(
    y: &EdwardsPoint,
    msg: &[u8],
    ids: &SignerIds,
    com_h: &Commitments,
    com_c: &Commitments,
) -> (Scalar, Scalar) {
    let mut list = [(ids.hot, com_h), (ids.cold, com_c)];
    // integer order of little-endian scalars = lexicographic order of reversed bytes
    list.sort_by_key(|(i, _)| {
        let mut b = i.to_bytes();
        b.reverse();
        b
    });
    let mut enc = Vec::with_capacity(2 * 96);
    for (i, c) in &list {
        enc.extend_from_slice(&i.to_bytes());
        enc.extend_from_slice(&c.hiding.compress().to_bytes());
        enc.extend_from_slice(&c.binding.compress().to_bytes());
    }
    let h4 = sha512(&[CONTEXT_STRING, b"msg", msg]);
    let h5 = sha512(&[CONTEXT_STRING, b"com", &enc]);
    let y_ser = y.compress().to_bytes();
    let rho = |i: &Scalar| {
        Scalar::from_bytes_mod_order_wide(&sha512(&[
            CONTEXT_STRING,
            b"rho",
            &y_ser,
            &h4,
            &h5,
            &i.to_bytes(),
        ]))
    };
    (rho(&ids.hot), rho(&ids.cold))
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Public per-signature values (computed independently by PROD and COLD).
#[derive(Clone, Debug)]
pub struct Session {
    /// `Y_p = Y`.
    pub key: Ed25519Key,
    /// Message (PureEdDSA: the full message).
    pub msg: Vec<u8>,
    /// Signer identifiers.
    pub ids: SignerIds,
    /// `(D_h, E_h)`
    pub com_h: Commitments,
    /// `(D_c, E_c)`
    pub com_c: Commitments,
    /// `ρ_h`
    pub rho_h: Scalar,
    /// `ρ_c`
    pub rho_c: Scalar,
    /// `R`
    pub r: EdwardsPoint,
    /// `c`
    pub c: Scalar,
    /// `λ_h`
    pub lambda_h: Scalar,
    /// `λ_c`
    pub lambda_c: Scalar,
}

impl Session {
    /// Compute all public session values.
    pub fn new(
        key: &Ed25519Key,
        ids: SignerIds,
        msg: &[u8],
        com_h: Commitments,
        com_c: Commitments,
    ) -> Result<Self, Error> {
        for p in [com_h.hiding, com_h.binding, com_c.hiding, com_c.binding] {
            if p.is_identity() {
                return Err(Error::IdentityCommitment);
            }
        }
        let (rho_h, rho_c) = binding_factors(&key.y, msg, &ids, &com_h, &com_c);
        let r = com_h.hiding + com_h.binding * rho_h + com_c.hiding + com_c.binding * rho_c;
        if r.is_identity() {
            return Err(Error::IdentityGroupCommitment);
        }
        let c = challenge(&r, &key.y, msg);
        Ok(Self {
            key: *key,
            msg: msg.to_vec(),
            ids,
            com_h,
            com_c,
            rho_h,
            rho_c,
            r,
            c,
            lambda_h: ids.lambda_hot(),
            lambda_c: ids.lambda_cold(),
        })
    }
}

/// PROD: `z_h = d_h + e_h·ρ_h + λ_h·s′_h·c`. Consumes the nonce pair.
pub fn prod_fragment(session: &Session, nonces_h: SecretNonces, s_prime_h: &Scalar) -> Scalar {
    let s = session;
    nonces_h.d + nonces_h.e * s.rho_h + s.lambda_h * s_prime_h * s.c
}

/// COLD: `z_h·G == D_h + ρ_h·E_h + λ_h·c·Y′_h`.
pub fn cold_check_fragment(
    session: &Session,
    z_h: &Scalar,
    y_h: &EdwardsPoint,
    delta: &Scalar,
) -> Result<(), Error> {
    let s = session;
    let y_h_prime = masked_verifying_share(y_h, delta);
    let lhs = EdwardsPoint::mul_base(z_h);
    let rhs = s.com_h.hiding + s.com_h.binding * s.rho_h + y_h_prime * (s.lambda_h * s.c);
    if lhs == rhs {
        Ok(())
    } else {
        Err(Error::FaultProdFragment)
    }
}

/// COLD: `z_c = d_c + e_c·ρ_c + λ_c·s′_c·c`.
pub fn cold_share(session: &Session, nonces_c: SecretNonces, s_prime_c: &Scalar) -> Scalar {
    let s = session;
    nonces_c.d + nonces_c.e * s.rho_c + s.lambda_c * s_prime_c * s.c
}

/// COLD, no checks: `z = z_h + z_c`, signature `ser(R) ‖ ser(z)`.
pub fn cold_combine(
    session: &Session,
    z_h: &Scalar,
    nonces_c: SecretNonces,
    s_prime_c: &Scalar,
) -> [u8; 64] {
    let z = z_h + cold_share(session, nonces_c, s_prime_c);
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&session.r.compress().to_bytes());
    sig[32..].copy_from_slice(&z.to_bytes());
    sig
}

/// COLD's full completion: check fragment, combine, verify strictly with ed25519-dalek.
pub fn cold_complete(
    session: &Session,
    z_h: &Scalar,
    nonces_c: SecretNonces,
    s_c: &Scalar,
    delta: &Scalar,
    y_h: &EdwardsPoint,
) -> Result<[u8; 64], Error> {
    cold_check_fragment(session, z_h, y_h, delta)?;
    let s_prime_c = cold_masked_share(s_c, delta, &session.ids);
    let sig = cold_combine(session, z_h, nonces_c, &s_prime_c);
    verify_strict(&session.key.to_bytes(), &session.msg, &sig)?;
    Ok(sig)
}

/// Independent verification: ed25519-dalek `verify_strict`.
pub fn verify_strict(y: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), Error> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(y).map_err(|_| Error::FaultFinalVerify)?;
    let sig = ed25519_dalek::Signature::from_bytes(sig);
    vk.verify_strict(msg, &sig).map_err(|_| Error::FaultFinalVerify)
}
