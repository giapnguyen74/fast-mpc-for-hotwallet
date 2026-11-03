//! HPKE sealing to an enclave `wrap_pk` (DESIGN SP3 §4, SP5 §3, SP6 step 3).
//!
//! Suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, base mode.

use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem as _,
    OpModeR, OpModeS, Serializable,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::CryptoError;

type Kem = X25519HkdfSha256;

/// A sealed payload: encapsulated key + ciphertext (with tag).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    #[serde(with = "serde_bytes")]
    pub enc: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ct: Vec<u8>,
}

/// Enclave wrap key (X25519).
pub struct WrapKey {
    sk: <Kem as hpke::Kem>::PrivateKey,
    pk: <Kem as hpke::Kem>::PublicKey,
}

impl WrapKey {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let (sk, pk) = Kem::gen_keypair(rng);
        WrapKey { sk, pk }
    }
    pub fn public(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.pk.to_bytes());
        out
    }
    /// Open a payload sealed to this key with the given `info` and `aad`. The plaintext is
    /// zeroized when dropped (it may hold halves, fragments or shares).
    pub fn open(&self, sealed: &Sealed, info: &[u8], aad: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&sealed.enc)
            .map_err(|_| CryptoError::Hpke)?;
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeR::Base,
            &self.sk,
            &enc,
            info,
            &sealed.ct,
            aad,
        )
        .map(zeroize::Zeroizing::new)
        .map_err(|_| CryptoError::Hpke)
    }
}

/// Seal `pt` to `wrap_pk` with `info` and `aad`.
pub fn seal<R: RngCore + CryptoRng>(
    wrap_pk: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
    rng: &mut R,
) -> Result<Sealed, CryptoError> {
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(wrap_pk).map_err(|_| CryptoError::Hpke)?;
    let (enc, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem, _>(
        &OpModeS::Base,
        &pk,
        info,
        pt,
        aad,
        rng,
    )
    .map_err(|_| CryptoError::Hpke)?;
    Ok(Sealed { enc: enc.to_bytes().to_vec(), ct })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_and_binding() {
        let mut rng = rand::thread_rng();
        let k = WrapKey::generate(&mut rng);
        let other = WrapKey::generate(&mut rng);
        let s = seal(&k.public(), b"info", b"aad", b"secret", &mut rng).unwrap();
        assert_eq!(k.open(&s, b"info", b"aad").unwrap().as_slice(), b"secret");
        // wrong recipient, wrong info, wrong aad, tampered ciphertext: all fail.
        assert!(other.open(&s, b"info", b"aad").is_err());
        assert!(k.open(&s, b"other", b"aad").is_err());
        assert!(k.open(&s, b"info", b"x").is_err());
        let mut t = s.clone();
        t.ct[0] ^= 1;
        assert!(k.open(&t, b"info", b"aad").is_err());
    }
}
