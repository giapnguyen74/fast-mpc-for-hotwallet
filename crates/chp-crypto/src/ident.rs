//! Enclave identity keys (DESIGN SP1 §3): Ed25519 `id_key`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{CryptoRng, RngCore};

use crate::{hash::sha256, CryptoError};

/// An Ed25519 identity key held inside a (simulated) enclave.
pub struct IdKey(SigningKey);

impl IdKey {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        IdKey(SigningKey::generate(rng))
    }
    pub fn from_seed(seed: [u8; 32]) -> Self {
        IdKey(SigningKey::from_bytes(&seed))
    }
    pub fn public(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}

/// Strict Ed25519 verification of `sig` by `pk` over `msg`.
pub fn verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(pk).map_err(|_| CryptoError::BadSignature)?;
    let sig = Signature::from_bytes(sig);
    vk.verify_strict(msg, &sig).map_err(|_| CryptoError::BadSignature)?;
    // `Verifier` kept in scope for non-strict users; CHP always uses strict.
    let _ = <VerifyingKey as Verifier<Signature>>::verify;
    Ok(())
}

/// `SHA-256(id_pk)`: the key id used in revocation lists and QR frames.
pub fn key_hash(pk: &[u8; 32]) -> [u8; 32] {
    sha256(pk)
}
