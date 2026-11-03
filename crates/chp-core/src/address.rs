//! Address book (DESIGN SP10 §2) as held by an engine, and the requester-side verifier (§4).

use chp_auth::{trust::Trust, AuthError};
use chp_crypto::{derive::derived_key, hash::tagged_hash};
use chp_wire::{
    decode_canonical,
    msgs::{AddressBook, AddressEntry, AddressProof, AddressStatus, KeyManifest, PartyCert},
    KeyId, MsgType, SignedMsg, B32,
};
use serde::{Deserialize, Serialize};

use crate::{digest::hash_of, keyring::decode_point};

/// The control statement every address entry is signed over (SP10 §2).
pub fn control_statement(chain: &str, key_id: &KeyId, path: &str, address: &str) -> [u8; 32] {
    tagged_hash(b"chp-address-control-v1", &[chain.as_bytes(), &key_id.0, path.as_bytes(), address.as_bytes()])
}

/// Derive the address of `path` for an ECDSA/EVM key from the manifest.
pub fn derive_address(m: &KeyManifest, path: &str) -> Option<String> {
    let y = decode_point(&m.group_key.0)?;
    if let Some(_id) = m.chain.strip_prefix("evm:") {
        return Some(chp_chain::evm::address_of_point(&derived_key(&m.key_id.0, &y, path)));
    }
    None
}

/// Verify an entry's control signature under the derived key (EVM: ECDSA over the statement).
pub fn verify_control_sig(m: &KeyManifest, e: &AddressEntry) -> bool {
    let Some(y) = decode_point(&m.group_key.0) else { return false };
    let Ok(sig): Result<[u8; 64], _> = e.control_sig.0.as_slice().try_into() else { return false };
    let st = control_statement(&e.chain, &m.key_id, &e.path, &e.address);
    chp_crypto::verify::ecdsa_verify(&derived_key(&m.key_id.0, &y, &e.path), &st, &sig).is_ok()
}

/// An engine's current address book.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BookView {
    pub book: Option<AddressBook>,
    pub bytes: Vec<u8>,
}

impl BookView {
    /// Verify and install a quorum-signed book; refuses `book_version` at or below the last.
    pub fn install(&mut self, trust: &Trust, bytes: &[u8], manifest: &KeyManifest, manifest_hash: &B32) -> Result<(), AuthError> {
        let b: AddressBook = trust.verify_quorum(bytes, MsgType::AddressBook)?;
        if b.manifest_hash != *manifest_hash || b.key_id != manifest.key_id {
            return Err(AuthError::Quorum("book does not reference this manifest".into()));
        }
        let last = self.book.as_ref().map(|b| b.book_version).unwrap_or(0);
        if b.book_version <= last {
            return Err(AuthError::Rollback { got: b.book_version, last });
        }
        self.book = Some(b);
        self.bytes = bytes.to_vec();
        Ok(())
    }

    /// Is `path` an `Active` entry of the current book for this key? (SP10 §2: a path outside
    /// the book can never be signed for.)
    pub fn path_active(&self, key_id: &KeyId, path: &str) -> bool {
        self.book.as_ref().is_some_and(|b| {
            b.key_id == *key_id && b.entries.iter().any(|e| e.path == path && e.status == AddressStatus::Active)
        })
    }

    pub fn find(&self, chain: &str, address: Option<&str>, path: Option<&str>) -> Option<&AddressEntry> {
        self.book.as_ref()?.entries.iter().find(|e| {
            e.chain == chain
                && address.is_none_or(|a| e.address.eq_ignore_ascii_case(a))
                && path.is_none_or(|p| e.path == p)
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProofError {
    #[error("step 1: {0}")]
    Quorum(String),
    #[error("step 2: book version {got} older than {last}")]
    OldBook { got: u64, last: u64 },
    #[error("step 3: address does not derive from the ceremony key")]
    Derivation,
    #[error("step 4: control signature invalid")]
    ControlSig,
    #[error("step 5: entry not active or not yet valid")]
    NotActive,
    #[error("step 6: PROD signature / nonce invalid")]
    ProdSig,
    #[error("entry not in book")]
    NotInBook,
}

/// Requester-side verification of an `AddressProof` (SP10 §4), in order. Needs only the pinned
/// roster (`trust`), the last accepted book version and the requester's nonce.
pub fn verify_proof(trust: &Trust, proof_frame: &[u8], nonce: &B32, last_book: u64, now: u64) -> Result<AddressEntry, ProofError> {
    let f: SignedMsg = decode_canonical(proof_frame).map_err(|e| ProofError::Quorum(e.to_string()))?;
    let p: AddressProof = decode_canonical(&f.body.0).map_err(|e| ProofError::Quorum(e.to_string()))?;
    // 1
    let m: KeyManifest = trust.verify_quorum(&p.manifest.0, MsgType::KeyManifest).map_err(|e| ProofError::Quorum(e.to_string()))?;
    let b: AddressBook = trust.verify_quorum(&p.book.0, MsgType::AddressBook).map_err(|e| ProofError::Quorum(e.to_string()))?;
    if b.manifest_hash != hash_of(&p.manifest.0) || b.key_id != m.key_id {
        return Err(ProofError::Quorum("book/manifest mismatch".into()));
    }
    if !b.entries.contains(&p.entry) {
        return Err(ProofError::NotInBook);
    }
    // 2
    if b.book_version < last_book {
        return Err(ProofError::OldBook { got: b.book_version, last: last_book });
    }
    // 3
    if derive_address(&m, &p.entry.path).as_deref() != Some(p.entry.address.as_str()) {
        return Err(ProofError::Derivation);
    }
    // 4
    if !verify_control_sig(&m, &p.entry) {
        return Err(ProofError::ControlSig);
    }
    // 5
    if p.entry.status != AddressStatus::Active || now < p.entry.valid_from {
        return Err(ProofError::NotActive);
    }
    // 6
    let (cert, _): (PartyCert, _) = trust.verify_cert(&p.prod_cert.0, now).map_err(|_| ProofError::ProdSig)?;
    chp_auth::link::check_standalone(&cert, chp_wire::Role::Upstream, proof_frame, MsgType::AddressProof)
        .or_else(|_| chp_auth::link::check_standalone(&cert, chp_wire::Role::Requester, proof_frame, MsgType::AddressProof))
        .map_err(|_| ProofError::ProdSig)?;
    if p.nonce != *nonce {
        return Err(ProofError::ProdSig);
    }
    Ok(p.entry)
}
