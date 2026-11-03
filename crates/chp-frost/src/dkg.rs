//! frost-core Pedersen DKG (SP2 §4) and conversion of its outputs to the raw
//! scalars/points used by [`crate::secp`] and [`crate::ed25519`].
//!
//! ⚠ **frost-secp256k1-tr post-processes the DKG output** (`Ciphersuite::post_dkg`):
//! it lifts the key to even y and adds a BIP86 TapTweak to every share and to the
//! group key. The "group key" a frost-secp256k1-tr DKG returns is therefore
//! `Y_lib = even(Y_raw) + H_TapTweak(Y_raw.x)·G`, not the raw Pedersen sum.
//! It is still a correct 2-of-3 Shamir sharing (`Σλ = 1`), and CHP uses it as `Y`
//! (the SP6 §4 formulas only need *some* consistently shared `Y`). See REVIEW.md.

use crate::Error;
use frost_core::keys::dkg::{part1, part2, part3};
use frost_core::keys::{KeyPackage, PublicKeyPackage};
use frost_core::{Ciphersuite, Identifier};
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::PrimeField;
use rand_core::{CryptoRng, RngCore};
use std::collections::BTreeMap;

fn ferr<E: core::fmt::Debug>(e: E) -> Error {
    Error::Frost(format!("{e:?}"))
}

/// Output of a 2-of-3 DKG among three parties.
pub struct DkgOutput<C: Ciphersuite> {
    /// Each party's key package.
    pub key_packages: BTreeMap<Identifier<C>, KeyPackage<C>>,
    /// The (agreed) public key package.
    pub public: PublicKeyPackage<C>,
    /// Each party's round-1 constant-term commitment `a_{i0}·G` (serialised).
    /// Their sum is the raw Pedersen group key *before* `Ciphersuite::post_dkg`;
    /// kept so that tests can show what frost-secp256k1-tr's post-processing does.
    pub constant_term_commitments: Vec<Vec<u8>>,
}

/// Run the three-round frost-core DKG (`part1/part2/part3`) for a 2-of-3 key
/// among `ids`, simulating all three parties in-process, and check that all
/// parties agree on the public key package (SP2 "Agreement").
pub fn run_dkg_2of3<C: Ciphersuite, R: RngCore + CryptoRng>(
    ids: [Identifier<C>; 3],
    rng: &mut R,
) -> Result<DkgOutput<C>, Error> {
    let mut r1_secret = BTreeMap::new();
    let mut r1_pkg = BTreeMap::new();
    for id in ids {
        let (s, p) = part1::<C, _>(id, 3, 2, &mut *rng).map_err(ferr)?;
        r1_secret.insert(id, s);
        r1_pkg.insert(id, p);
    }
    let mut constant_term_commitments = Vec::new();
    for p in r1_pkg.values() {
        constant_term_commitments.push(p.commitment().serialize().map_err(ferr)?.swap_remove(0));
    }
    let mut r2_secret = BTreeMap::new();
    let mut r2_out: BTreeMap<Identifier<C>, BTreeMap<Identifier<C>, _>> = BTreeMap::new();
    for id in ids {
        let others: BTreeMap<_, _> =
            r1_pkg.iter().filter(|(k, _)| **k != id).map(|(k, v)| (*k, v.clone())).collect();
        let (s, out) = part2(r1_secret.remove(&id).unwrap(), &others).map_err(ferr)?;
        r2_secret.insert(id, s);
        r2_out.insert(id, out);
    }
    let mut key_packages = BTreeMap::new();
    let mut publics = Vec::new();
    for id in ids {
        let r1_others: BTreeMap<_, _> =
            r1_pkg.iter().filter(|(k, _)| **k != id).map(|(k, v)| (*k, v.clone())).collect();
        let r2_for_me: BTreeMap<_, _> = r2_out
            .iter()
            .filter(|(from, _)| **from != id)
            .map(|(from, m)| (*from, m[&id].clone()))
            .collect();
        let (kp, pkp) = part3(&r2_secret[&id], &r1_others, &r2_for_me).map_err(ferr)?;
        key_packages.insert(id, kp);
        publics.push(pkp);
    }
    if publics.iter().any(|p| p != &publics[0]) {
        return Err(Error::Frost("parties disagree on the public key package".into()));
    }
    Ok(DkgOutput { key_packages, public: publics.swap_remove(0), constant_term_commitments })
}

// ---------------------------------------------------------------------------
// secp256k1-tr conversions
// ---------------------------------------------------------------------------

/// Raw view of one party's secp256k1 key material.
#[derive(Clone, Copy, Debug)]
pub struct SecpParty {
    /// Identifier scalar `i`.
    pub id: k256::Scalar,
    /// Long-term share `s_i`.
    pub share: k256::Scalar,
    /// Verifying share `Y_i = s_i·G`.
    pub verifying_share: k256::ProjectivePoint,
}

fn secp_scalar(bytes: &[u8]) -> Result<k256::Scalar, Error> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidScalar)?;
    Option::from(k256::Scalar::from_repr(arr.into())).ok_or(Error::InvalidScalar)
}

/// Decode a 33-byte SEC1 compressed secp256k1 point.
pub fn secp_point(bytes: &[u8]) -> Result<k256::ProjectivePoint, Error> {
    let ep = k256::EncodedPoint::from_bytes(bytes).map_err(|_| Error::InvalidPoint)?;
    Option::<k256::AffinePoint>::from(k256::AffinePoint::from_encoded_point(&ep))
        .map(k256::ProjectivePoint::from)
        .ok_or(Error::InvalidPoint)
}

/// Identifier scalar (frost-secp256k1-tr serialises identifiers as 32-byte big-endian).
pub fn secp_id(id: &frost_secp256k1_tr::Identifier) -> Result<k256::Scalar, Error> {
    secp_scalar(&id.serialize())
}

/// Raw share material from a frost-secp256k1-tr key package.
pub fn secp_party(kp: &frost_secp256k1_tr::keys::KeyPackage) -> Result<SecpParty, Error> {
    Ok(SecpParty {
        id: secp_id(kp.identifier())?,
        share: secp_scalar(&kp.signing_share().serialize())?,
        verifying_share: secp_point(&kp.verifying_share().serialize().map_err(ferr)?)?,
    })
}

/// Group key `Y` from a frost-secp256k1-tr public key package.
pub fn secp_group_key(
    pkp: &frost_secp256k1_tr::keys::PublicKeyPackage,
) -> Result<k256::ProjectivePoint, Error> {
    secp_point(&pkp.verifying_key().serialize().map_err(ferr)?)
}

/// Verifying share `Y_i` of a given identifier (as COLD reads it from the manifest).
pub fn secp_verifying_share(
    pkp: &frost_secp256k1_tr::keys::PublicKeyPackage,
    id: &frost_secp256k1_tr::Identifier,
) -> Result<k256::ProjectivePoint, Error> {
    let vs = pkp.verifying_shares().get(id).ok_or(Error::BadIdentifiers)?;
    secp_point(&vs.serialize().map_err(ferr)?)
}

// ---------------------------------------------------------------------------
// Ed25519 conversions
// ---------------------------------------------------------------------------

/// Raw view of one party's Ed25519 key material.
#[derive(Clone, Copy, Debug)]
pub struct EdParty {
    /// Identifier scalar `i`.
    pub id: curve25519_dalek::Scalar,
    /// Long-term share `s_i`.
    pub share: curve25519_dalek::Scalar,
    /// Verifying share `Y_i`.
    pub verifying_share: curve25519_dalek::EdwardsPoint,
}

fn ed_scalar(bytes: &[u8]) -> Result<curve25519_dalek::Scalar, Error> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidScalar)?;
    crate::ed25519::decode_scalar(&arr)
}

fn ed_point(bytes: &[u8]) -> Result<curve25519_dalek::EdwardsPoint, Error> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidPoint)?;
    crate::ed25519::decode_point(&arr)
}

/// Identifier scalar (frost-ed25519 serialises identifiers as 32-byte little-endian).
pub fn ed_id(id: &frost_ed25519::Identifier) -> Result<curve25519_dalek::Scalar, Error> {
    ed_scalar(&id.serialize())
}

/// Raw share material from a frost-ed25519 key package.
pub fn ed_party(kp: &frost_ed25519::keys::KeyPackage) -> Result<EdParty, Error> {
    Ok(EdParty {
        id: ed_id(kp.identifier())?,
        share: ed_scalar(&kp.signing_share().serialize())?,
        verifying_share: ed_point(&kp.verifying_share().serialize().map_err(ferr)?)?,
    })
}

/// Group key `Y` from a frost-ed25519 public key package.
pub fn ed_group_key(
    pkp: &frost_ed25519::keys::PublicKeyPackage,
) -> Result<curve25519_dalek::EdwardsPoint, Error> {
    ed_point(&pkp.verifying_key().serialize().map_err(ferr)?)
}

/// Verifying share `Y_i` of a given identifier.
pub fn ed_verifying_share(
    pkp: &frost_ed25519::keys::PublicKeyPackage,
    id: &frost_ed25519::Identifier,
) -> Result<curve25519_dalek::EdwardsPoint, Error> {
    let vs = pkp.verifying_shares().get(id).ok_or(Error::BadIdentifiers)?;
    ed_point(&vs.serialize().map_err(ferr)?)
}
