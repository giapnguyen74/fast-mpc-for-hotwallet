//! Domain-separated, length-prefixed hashing (DESIGN SP1 §5: "every encoding is canonical,
//! length-prefixed and domain-separated").
//!
//! `tagged_hash(tag, fields) = SHA-256( u32_be(|tag|) ‖ tag ‖ Σ ( u32_be(|f|) ‖ f ) )`.
//! The same framing is used by `chp-frost`.

use sha2::{Digest, Sha256};

pub type Hash32 = [u8; 32];

/// Length-prefixed, tagged SHA-256.
pub fn tagged_hash(tag: &[u8], fields: &[&[u8]]) -> Hash32 {
    let mut h = Sha256::new();
    h.update((tag.len() as u32).to_be_bytes());
    h.update(tag);
    for f in fields {
        h.update((f.len() as u32).to_be_bytes());
        h.update(f);
    }
    h.finalize().into()
}

/// Plain SHA-256.
pub fn sha256(data: &[u8]) -> Hash32 {
    Sha256::digest(data).into()
}

/// Keccak-256 (EVM addresses and sighashes).
pub fn keccak256(data: &[u8]) -> Hash32 {
    use sha3::Keccak256;
    Keccak256::digest(data).into()
}

/// Short hex fingerprint for logs and operator displays.
pub fn fingerprint(h: &Hash32) -> String {
    hex::encode(&h[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_prevents_concatenation_ambiguity() {
        // ("ab","c") and ("a","bc") must hash differently.
        assert_ne!(tagged_hash(b"t", &[b"ab", b"c"]), tagged_hash(b"t", &[b"a", b"bc"]));
        // tag is separated from fields.
        assert_ne!(tagged_hash(b"ta", &[b"g"]), tagged_hash(b"t", &[b"ag"]));
    }

    #[test]
    fn keccak_known_vector() {
        assert_eq!(
            hex::encode(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }
}
