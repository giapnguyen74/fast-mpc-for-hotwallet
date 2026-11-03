//! CHP adapter over the vendored DKLs23 library (`thirdparty/dkls23`).
//!
//! Linked only by HOT, COLD and the ceremony tooling. PROD never depends on this crate
//! (DESIGN rule 6: no live path into key management); `scripts/check-capabilities.sh`
//! enforces it.

pub mod dkls;
pub mod presign;

pub use sl_dkls23::keygen::Keyshare;
pub use sl_dkls23::sign::PreSign;

use chp_crypto::ecdsa::EcdsaHalf;

/// Extract a CHP half from the library's presign output.
pub fn half_from_presign(p: &PreSign) -> EcdsaHalf {
    EcdsaHalf::from_parts(p.final_session_id, *p.chp_big_r(), *p.chp_public_key(), *p.chp_phi(), *p.chp_s0(), *p.chp_s1())
}

/// Serialise a key share (for sealing inside the simulated enclave or an HPKE package). The
/// buffer is zeroized when dropped (the library's `Keyshare` itself is `ZeroizeOnDrop`).
pub fn share_to_bytes(k: &Keyshare) -> zeroize::Zeroizing<Vec<u8>> {
    zeroize::Zeroizing::new(k.as_slice().to_vec())
}

/// Parse a key share.
pub fn share_from_bytes(b: &[u8]) -> Option<Keyshare> {
    Keyshare::from_bytes(b)
}
