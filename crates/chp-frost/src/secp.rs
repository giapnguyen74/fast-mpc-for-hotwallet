//! δ-split FROST signing for Taproot (BIP340 output), DESIGN SP6 §4.2.
//!
//! All arithmetic is on raw `k256` scalars/points. frost-core is used only for
//! DKG (see [`crate::dkg`]); its signing and its Taproot tweak are **not** used.
//!
//! ## Public session values (computed identically by PROD and COLD)
//!
//! ```text
//! ρ_j = H1( ser(Y_p) ‖ H4(m) ‖ H5(encode_group_commitment_list(B)) ‖ ser(i_j) )     RFC 9591 §4.4
//! R   = Σ_j (D_j + ρ_j·E_j)
//! g_R = +1 if R has even y, else −1
//! c   = int( hash_BIP0340/challenge( R.x ‖ Q.x ‖ m ) ) mod n                         BIP340
//! λ_h = i_c/(i_c − i_h),   λ_c = i_h/(i_h − i_c)                                     Lagrange at 0
//! ```
//!
//! Exactly what is hashed (ciphersuite FROST-secp256k1-SHA256-TR-v1, matching
//! frost-secp256k1-tr 3.0 byte for byte — tested):
//! - `ser(Y_p)` = 33-byte SEC1 of the **even-y lift** `g_Q·Q`, i.e. `0x02 ‖ Q.x`.
//!   (Y_p = Q is x-only on chain; the lift makes the encoding canonical.)
//! - `H4(m) = SHA-256("FROST-secp256k1-SHA256-TR-v1" ‖ "msg" ‖ m)`
//! - `H5(x) = SHA-256("FROST-secp256k1-SHA256-TR-v1" ‖ "com" ‖ x)`
//! - `encode_group_commitment_list(B)` = for each signer in increasing identifier
//!   order: `ser(i_j) ‖ ser(D_j) ‖ ser(E_j)`, identifiers as 32-byte big-endian
//!   scalars, points 33-byte SEC1 compressed.
//! - `H1(x) = hash_to_field(x)` with `expand_message_xmd(SHA-256)`,
//!   DST = `"FROST-secp256k1-SHA256-TR-v1" ‖ "rho"` (RFC 9380 §5.2, one element).
//!
//! ## Fragment, check, completion
//!
//! ```text
//! PROD:  z_h = g_R·(d_h + e_h·ρ_h) + g·λ_h·s′_h·c                   s′_h = s_h + δ
//! COLD:  z_h·G == g_R·(D_h + ρ_h·E_h) + g·λ_h·c·Y′_h                 Y′_h = Y_h + δ·G
//!        z_c  = g_R·(d_c + e_c·ρ_c) + g·λ_c·s′_c·c                   s′_c = s_c + (i_c/i_h)·δ
//!        z    = z_h + z_c + c·t_eff,     signature = (R.x, z)
//! ```

use crate::derive::sec1_compressed;
use crate::hash::bip340_tagged_hash;
use crate::taproot::{has_odd_y, sign_factor, x_only, TaprootKey};
use crate::Error;
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::hash2curve::{hash_to_field, ExpandMsgXmd};
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::{Field, PrimeField};
use k256::{ProjectivePoint, Scalar, U256};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

/// RFC 9591 context string of the BIP340 (Taproot) FROST ciphersuite.
pub const CONTEXT_STRING: &[u8] = b"FROST-secp256k1-SHA256-TR-v1";

// ---------------------------------------------------------------------------
// Nonces
// ---------------------------------------------------------------------------

/// One side's secret nonce pair `(d, e)` for one presignature.
///
/// Not `Clone`: a nonce pair is consumed (moved) by exactly one signing call.
/// Reusing a pair leaks the share (see tests `nonce_reuse_*`), so storage
/// must be take = delete (SP6 step 3/4).
#[derive(Debug)]
pub struct SecretNonces {
    d: Scalar,
    e: Scalar,
}

/// Public nonce commitments `(D, E) = (d·G, e·G)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitments {
    /// Hiding commitment `D = d·G`.
    pub hiding: ProjectivePoint,
    /// Binding commitment `E = e·G`.
    pub binding: ProjectivePoint,
}

impl SecretNonces {
    /// Rebuild from stored scalars (deserialisation). Both must be nonzero.
    pub fn from_scalars(d: Scalar, e: Scalar) -> Result<Self, Error> {
        if bool::from(d.is_zero()) || bool::from(e.is_zero()) {
            return Err(Error::InvalidScalar);
        }
        Ok(Self { d, e })
    }
    /// The stored scalars `(d, e)` (for sealing into a half; handle as secret).
    pub fn to_scalars(&self) -> (Scalar, Scalar) {
        (self.d, self.e)
    }
    /// `(d·G, e·G)`.
    pub fn commitments(&self) -> Commitments {
        Commitments {
            hiding: ProjectivePoint::GENERATOR * self.d,
            binding: ProjectivePoint::GENERATOR * self.e,
        }
    }
}

fn random_nonzero<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    loop {
        let s = Scalar::random(&mut *rng);
        if !bool::from(s.is_zero()) {
            return s;
        }
    }
}

/// Generate one nonce pair and its commitments (presign, SP4). Used by both sides.
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
// Signer set, Lagrange, δ split
// ---------------------------------------------------------------------------

/// FROST identifier scalars of the signer set {HOT, COLD}.
///
/// These are the **identifier scalars** (frost-core `Identifier::to_scalar`),
/// not party labels: for `Identifier::try_from(1u16)` it is 1, for
/// `Identifier::derive(..)` it is a hash. Use [`crate::dkg`] to convert.
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
        if bool::from(hot.is_zero()) || bool::from(cold.is_zero()) || hot == cold {
            return Err(Error::BadIdentifiers);
        }
        Ok(Self { hot, cold })
    }
    /// `λ_h = i_c/(i_c − i_h)`.
    pub fn lambda_hot(&self) -> Scalar {
        self.cold * (self.cold - self.hot).invert().unwrap()
    }
    /// `λ_c = i_h/(i_h − i_c)`.
    pub fn lambda_cold(&self) -> Scalar {
        self.hot * (self.hot - self.cold).invert().unwrap()
    }
    /// `i_c/i_h`, the factor applied to δ in COLD's share.
    pub fn mask_ratio(&self) -> Scalar {
        self.cold * self.hot.invert().unwrap()
    }
}

/// HOT, SP5 step 1: `s′_h = s_h + δ` with fresh random nonzero `δ`. Returns `(s′_h, δ)`.
pub fn split_share<R: RngCore + CryptoRng>(s_h: &Scalar, rng: &mut R) -> (Scalar, Scalar) {
    let delta = random_nonzero(rng);
    (*s_h + delta, delta)
}

/// COLD: `s′_c = s_c + (i_c/i_h)·δ`.
pub fn cold_masked_share(s_c: &Scalar, delta: &Scalar, ids: &SignerIds) -> Scalar {
    *s_c + ids.mask_ratio() * delta
}

/// COLD: `Y′_h = Y_h + δ·G`.
pub fn masked_verifying_share(y_h: &ProjectivePoint, delta: &Scalar) -> ProjectivePoint {
    *y_h + ProjectivePoint::GENERATOR * delta
}

// ---------------------------------------------------------------------------
// Hashes
// ---------------------------------------------------------------------------

fn h1(input: &[u8]) -> Scalar {
    let mut out = [Scalar::ZERO];
    hash_to_field::<ExpandMsgXmd<Sha256>, Scalar>(&[input], &[CONTEXT_STRING, b"rho"], &mut out)
        .expect("expand_message_xmd cannot fail for these lengths");
    out[0]
}

fn h4(m: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(CONTEXT_STRING).chain_update(b"msg").chain_update(m).finalize().into()
}

fn h5(m: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(CONTEXT_STRING).chain_update(b"com").chain_update(m).finalize().into()
}

fn ser_id(i: &Scalar) -> [u8; 32] {
    i.to_repr().into()
}

/// BIP340 challenge `e = int(hash_BIP0340/challenge(r_x ‖ p_x ‖ m)) mod n`.
pub fn bip340_challenge(r_x: &[u8; 32], p_x: &[u8; 32], msg: &[u8]) -> Scalar {
    let h = bip340_tagged_hash("BIP0340/challenge", &[r_x, p_x, msg]);
    <Scalar as Reduce<U256>>::reduce_bytes(&h.into())
}

/// RFC 9591 binding factors `(ρ_h, ρ_c)` for the two-signer list `B`.
///
/// `y_p_ser` is the encoding of `Y_p` (for Taproot: [`TaprootKey::q_even_sec1`]).
pub fn binding_factors(
    y_p_ser: &[u8; 33],
    msg: &[u8],
    ids: &SignerIds,
    com_h: &Commitments,
    com_c: &Commitments,
) -> (Scalar, Scalar) {
    // encode_group_commitment_list: sorted by identifier as an integer.
    let mut list = [(ids.hot, com_h), (ids.cold, com_c)];
    list.sort_by_key(|(i, _)| ser_id(i)); // big-endian bytes sort == integer sort
    let mut enc = Vec::with_capacity(2 * (32 + 33 + 33));
    for (i, c) in &list {
        enc.extend_from_slice(&ser_id(i));
        enc.extend_from_slice(&sec1_compressed(&c.hiding));
        enc.extend_from_slice(&sec1_compressed(&c.binding));
    }
    let mut prefix = Vec::with_capacity(33 + 32 + 32);
    prefix.extend_from_slice(y_p_ser);
    prefix.extend_from_slice(&h4(msg));
    prefix.extend_from_slice(&h5(&enc));
    let rho = |i: &Scalar| {
        let mut inp = prefix.clone();
        inp.extend_from_slice(&ser_id(i));
        h1(&inp)
    };
    (rho(&ids.hot), rho(&ids.cold))
}

// ---------------------------------------------------------------------------
// Session (public data, computed independently by PROD and COLD)
// ---------------------------------------------------------------------------

/// Public per-signature values of SP6 §4.2. PROD and COLD each build this
/// from public data only (key, path, message, both commitments, identifiers).
#[derive(Clone, Debug)]
pub struct Session {
    /// Per-path Taproot values (`Y_p = Q`, `g`, `t_eff`, …).
    pub key: TaprootKey,
    /// The message (BIP341 sighash, 32 bytes in CHP; any length is accepted as in BIP340).
    pub msg: Vec<u8>,
    /// Signer identifiers.
    pub ids: SignerIds,
    /// HOT's (PROD's) commitments `(D_h, E_h)`.
    pub com_h: Commitments,
    /// COLD's commitments `(D_c, E_c)`.
    pub com_c: Commitments,
    /// `ρ_h`
    pub rho_h: Scalar,
    /// `ρ_c`
    pub rho_c: Scalar,
    /// Group commitment `R` (not lifted).
    pub r: ProjectivePoint,
    /// `g_R` (±1).
    pub g_r: Scalar,
    /// Challenge `c`.
    pub c: Scalar,
    /// `λ_h`
    pub lambda_h: Scalar,
    /// `λ_c`
    pub lambda_c: Scalar,
}

impl Session {
    /// Compute all public session values.
    pub fn new(
        key: &TaprootKey,
        ids: SignerIds,
        msg: &[u8],
        com_h: Commitments,
        com_c: Commitments,
    ) -> Result<Self, Error> {
        for p in [com_h.hiding, com_h.binding, com_c.hiding, com_c.binding] {
            if bool::from(p.is_identity()) {
                return Err(Error::IdentityCommitment);
            }
        }
        let (rho_h, rho_c) = binding_factors(&key.q_even_sec1(), msg, &ids, &com_h, &com_c);
        let r = com_h.hiding + com_h.binding * rho_h + com_c.hiding + com_c.binding * rho_c;
        if bool::from(r.is_identity()) {
            return Err(Error::IdentityGroupCommitment);
        }
        let g_r = sign_factor(has_odd_y(&r));
        let c = bip340_challenge(&x_only(&r), &key.q_xonly(), msg);
        Ok(Self {
            key: *key,
            msg: msg.to_vec(),
            ids,
            com_h,
            com_c,
            rho_h,
            rho_c,
            r,
            g_r,
            c,
            lambda_h: ids.lambda_hot(),
            lambda_c: ids.lambda_cold(),
        })
    }

    /// `true` iff `R` has odd y (`g_R = −1`).
    pub fn r_odd(&self) -> bool {
        self.g_r != Scalar::ONE
    }
}

// ---------------------------------------------------------------------------
// PROD
// ---------------------------------------------------------------------------

/// PROD's fragment: `z_h = g_R·(d_h + e_h·ρ_h) + g·λ_h·s′_h·c`.
///
/// Consumes the nonce pair (it must have been taken = deleted from the store).
pub fn prod_fragment(session: &Session, nonces_h: SecretNonces, s_prime_h: &Scalar) -> Scalar {
    let s = session;
    s.g_r * (nonces_h.d + nonces_h.e * s.rho_h) + s.key.g * s.lambda_h * s_prime_h * s.c
}

// ---------------------------------------------------------------------------
// COLD
// ---------------------------------------------------------------------------

/// COLD's check: `z_h·G == g_R·(D_h + ρ_h·E_h) + g·λ_h·c·Y′_h` with `Y′_h = Y_h + δ·G`.
pub fn cold_check_fragment(
    session: &Session,
    z_h: &Scalar,
    y_h: &ProjectivePoint,
    delta: &Scalar,
) -> Result<(), Error> {
    let s = session;
    let y_h_prime = masked_verifying_share(y_h, delta);
    let lhs = ProjectivePoint::GENERATOR * z_h;
    let rhs = (s.com_h.hiding + s.com_h.binding * s.rho_h) * s.g_r
        + y_h_prime * (s.key.g * s.lambda_h * s.c);
    if lhs == rhs {
        Ok(())
    } else {
        Err(Error::FaultProdFragment)
    }
}

/// COLD's share: `z_c = g_R·(d_c + e_c·ρ_c) + g·λ_c·s′_c·c`.
pub fn cold_share(session: &Session, nonces_c: SecretNonces, s_prime_c: &Scalar) -> Scalar {
    let s = session;
    s.g_r * (nonces_c.d + nonces_c.e * s.rho_c) + s.key.g * s.lambda_c * s_prime_c * s.c
}

/// COLD's combination **without any check**: `z = z_h + z_c + c·t_eff`,
/// signature `R.x ‖ z` (64 bytes). Exposed for tests and for callers that run
/// the checks themselves; production code should call [`cold_complete`].
pub fn cold_combine(
    session: &Session,
    z_h: &Scalar,
    nonces_c: SecretNonces,
    s_prime_c: &Scalar,
) -> [u8; 64] {
    let z_c = cold_share(session, nonces_c, s_prime_c);
    let z = *z_h + z_c + session.c * session.key.t_eff;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&x_only(&session.r));
    sig[32..].copy_from_slice(&z.to_repr());
    sig
}

/// COLD's full completion (SP6 step 5):
/// 1. [`cold_check_fragment`] → else `FAULT_PROD_FRAGMENT`;
/// 2. `s′_c = s_c + (i_c/i_h)·δ`, [`cold_combine`];
/// 3. independent verification with libsecp256k1 against `Q.x` → else `FAULT_FINAL_VERIFY`.
pub fn cold_complete(
    session: &Session,
    z_h: &Scalar,
    nonces_c: SecretNonces,
    s_c: &Scalar,
    delta: &Scalar,
    y_h: &ProjectivePoint,
) -> Result<[u8; 64], Error> {
    cold_check_fragment(session, z_h, y_h, delta)?;
    let s_prime_c = cold_masked_share(s_c, delta, &session.ids);
    let sig = cold_combine(session, z_h, nonces_c, &s_prime_c);
    verify_bip340(&session.key.q_xonly(), &session.msg, &sig)?;
    Ok(sig)
}

// ---------------------------------------------------------------------------
// Independent verification
// ---------------------------------------------------------------------------

/// BIP340 verification with libsecp256k1 (the `secp256k1` crate), independent
/// of k256 and frost-core.
pub fn verify_bip340(q_xonly: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), Error> {
    let pk = secp256k1::XOnlyPublicKey::from_byte_array(q_xonly).map_err(|_| Error::FaultFinalVerify)?;
    let sig = secp256k1::schnorr::Signature::from_byte_array(*sig);
    secp256k1::SECP256K1.verify_schnorr(&sig, msg, &pk).map_err(|_| Error::FaultFinalVerify)
}
