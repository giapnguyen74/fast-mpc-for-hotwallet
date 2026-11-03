//! Digests and session ids (all length-prefixed and domain-separated).

use chp_crypto::hash::tagged_hash;
use chp_wire::{encode, msgs::WakeOpen, KeyId, PresigId, B32};

/// Batch digest (DESIGN SP4 §4 step 4):
/// `H(batch_id ‖ key_id ‖ key_version ‖ path ‖ presig_ids ‖ public parts)`, ids and public parts
/// in id order. Computed independently by HOT, COLD and PROD.
pub fn batch_digest(batch_id: &B32, key_id: &KeyId, key_version: u32, path: &str, items: &[(PresigId, Vec<u8>)]) -> B32 {
    let mut ids = Vec::new();
    let mut parts = Vec::new();
    let mut sorted: Vec<&(PresigId, Vec<u8>)> = items.iter().collect();
    sorted.sort_by_key(|(id, _)| *id);
    for (id, p) in sorted {
        ids.extend_from_slice(&id.to_be_bytes());
        parts.extend_from_slice(&(p.len() as u32).to_be_bytes());
        parts.extend_from_slice(p);
    }
    B32(tagged_hash(
        b"chp-batch-v1",
        &[&batch_id.0, &key_id.0, &key_version.to_be_bytes(), path.as_bytes(), &ids, &parts],
    ))
}

/// Session id (DESIGN SP6 step 3): `H(chain, key_id, key_version, presig_id, {HOT, COLD}, m, path)`.
pub fn ssid(chain: &str, key_id: &KeyId, key_version: u32, presig_id: PresigId, m: &[u8; 32], path: &str) -> B32 {
    B32(tagged_hash(
        b"chp-ssid-v1",
        &[chain.as_bytes(), &key_id.0, &key_version.to_be_bytes(), &presig_id.to_be_bytes(), b"HOT,COLD", m, path.as_bytes()],
    ))
}

/// Digest of a `WakeOpen`, displayed to both operators (DESIGN SP4 §2).
pub fn wake_digest(w: &WakeOpen) -> B32 {
    B32(tagged_hash(b"chp-wake-v1", &[&encode(w)]))
}

/// AAD of an HPKE payload bound to the message it travels in: `H(message without ciphertext)`.
pub fn aad_of<T: serde::Serialize>(tag: &[u8], without_ct: &T) -> [u8; 32] {
    tagged_hash(tag, &[&encode(without_ct)])
}

/// Evidence hash of a frame (DESIGN SP7: `FreezeNotice.evidence_hash`).
pub fn evidence(frame: &[u8]) -> B32 {
    B32(chp_crypto::hash::sha256(frame))
}

/// SHA-256 of an encoded object (manifest hash, cert hash).
pub fn hash_of(bytes: &[u8]) -> B32 {
    B32(chp_crypto::hash::sha256(bytes))
}
