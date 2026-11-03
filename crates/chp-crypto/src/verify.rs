//! Independent ECDSA verification with libsecp256k1 (DESIGN SP6 step 5: "a verifier
//! implementation independent of the MPC library"). The MPC library uses `k256`.

use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint};

use crate::CryptoError;

/// Verify a low-s ECDSA signature `(r, s)` (64 bytes compact) over a 32-byte prehash.
pub fn ecdsa_verify(pk: &ProjectivePoint, prehash: &[u8; 32], sig64: &[u8; 64]) -> Result<(), CryptoError> {
    use secp256k1::{ecdsa::Signature, Message, PublicKey, SECP256K1};
    let pk = PublicKey::from_slice(pk.to_affine().to_encoded_point(true).as_bytes())
        .map_err(|_| CryptoError::Encoding)?;
    let sig = Signature::from_compact(sig64).map_err(|_| CryptoError::Encoding)?;
    // libsecp256k1 rejects high-s signatures in `verify_ecdsa`: CHP always emits low-s.
    SECP256K1
        .verify_ecdsa(&Message::from_digest(*prehash), &sig, &pk)
        .map_err(|_| CryptoError::FinalVerify)
}

/// Recover the public key from a recoverable signature (used by EVM-style checks).
pub fn ecdsa_recover(prehash: &[u8; 32], sig64: &[u8; 64], recid: u8) -> Result<[u8; 65], CryptoError> {
    use secp256k1::{ecdsa::{RecoverableSignature, RecoveryId}, Message, SECP256K1};
    let rid = RecoveryId::try_from(recid as i32).map_err(|_| CryptoError::Encoding)?;
    let sig = RecoverableSignature::from_compact(sig64, rid).map_err(|_| CryptoError::Encoding)?;
    let pk = SECP256K1
        .recover_ecdsa(&Message::from_digest(*prehash), &sig)
        .map_err(|_| CryptoError::FinalVerify)?;
    Ok(pk.serialize_uncompressed())
}
