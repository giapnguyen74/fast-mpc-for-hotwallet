//! Hash conventions.
//!
//! **CHP tagged hash** (shared with the other CHP crates — must stay identical):
//!
//! ```text
//! tagged_hash(tag, fields) = SHA-256( u32_be(len(tag)) ‖ tag ‖ for each field: u32_be(len(field)) ‖ field )
//! ```
//!
//! [`tagged_hash_512`] is the same framing with SHA-512; it is used only where a
//! 64-byte digest is needed for a wide reduction mod ℓ (Ed25519).
//!
//! **BIP340 tagged hash** (Bitcoin; *different* framing, used for `TapTweak` and
//! `BIP0340/challenge`):
//!
//! ```text
//! hash_tag(x) = SHA-256( SHA-256(tag) ‖ SHA-256(tag) ‖ x )
//! ```

use sha2::{Digest, Sha256, Sha512};

fn frame<D: Digest>(h: &mut D, tag: &[u8], fields: &[&[u8]]) {
    h.update((tag.len() as u32).to_be_bytes());
    h.update(tag);
    for f in fields {
        h.update((f.len() as u32).to_be_bytes());
        h.update(f);
    }
}

/// CHP tagged hash, SHA-256 version (see module docs).
pub fn tagged_hash(tag: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    frame(&mut h, tag, fields);
    h.finalize().into()
}

/// CHP tagged hash, SHA-512 version (same framing; for wide reduction mod ℓ).
pub fn tagged_hash_512(tag: &[u8], fields: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    frame(&mut h, tag, fields);
    h.finalize().into()
}

/// BIP340 tagged hash: `SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ data[0] ‖ data[1] ‖ …)`.
pub fn bip340_tagged_hash(tag: &str, data: &[&[u8]]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    for d in data {
        h.update(d);
    }
    h.finalize().into()
}
