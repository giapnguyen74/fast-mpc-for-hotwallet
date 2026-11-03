//! Quorum signing (offline custodians, DESIGN SP1 §2, §7).

use chp_crypto::{hash::tagged_hash, ident::IdKey};
use chp_wire::{encode, Bytes, MsgType, QSig, QuorumSignedMsg, B32, B64};
use serde::Serialize;

/// Domain-tagged digest every member signs: `H("chp-quorum-v1" ‖ type ‖ body)`.
pub fn quorum_digest(t: u16, body: &[u8]) -> [u8; 32] {
    tagged_hash(b"chp-quorum-v1", &[&t.to_be_bytes(), body])
}

/// A set of custodian keys (each custodian holds one; here they sign together for brevity).
pub struct Custodians(pub Vec<IdKey>);

impl Custodians {
    pub fn generate(n: usize) -> Self {
        let mut rng = rand::thread_rng();
        Custodians((0..n).map(|_| IdKey::generate(&mut rng)).collect())
    }
    pub fn members(&self) -> Vec<B32> {
        self.0.iter().map(|k| B32(k.public())).collect()
    }
    /// Sign `body` with the first `m` custodians.
    pub fn sign<T: Serialize>(&self, m: usize, t: MsgType, body: &T) -> Vec<u8> {
        let body = encode(body);
        let d = quorum_digest(t.code(), &body);
        let sigs = self.0.iter().take(m).map(|k| QSig { member: B32(k.public()), sig: B64(k.sign(&d)) }).collect();
        encode(&QuorumSignedMsg { msg_type: t.code(), body: Bytes(body), sigs })
    }
}
