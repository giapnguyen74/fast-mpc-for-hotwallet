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

/// An engine's address books, one per key (security review round 2: a single shared book let
/// one key's book disable another's paths).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BookView {
    books: std::collections::BTreeMap<KeyId, (AddressBook, Vec<u8>)>,
}

impl BookView {
    /// Verify and install a quorum-signed book for its key; refuses `book_version` at or below
    /// the last one accepted **for that key**.
    pub fn install(&mut self, trust: &Trust, bytes: &[u8], manifest: &KeyManifest, manifest_hash: &B32) -> Result<(), AuthError> {
        let b: AddressBook = trust.verify_quorum(bytes, MsgType::AddressBook)?;
        if b.manifest_hash != *manifest_hash || b.key_id != manifest.key_id {
            return Err(AuthError::Quorum("book does not reference this manifest".into()));
        }
        let last = self.books.get(&b.key_id).map(|(b, _)| b.book_version).unwrap_or(0);
        if b.book_version <= last {
            return Err(AuthError::Rollback { got: b.book_version, last });
        }
        self.books.insert(b.key_id, (b, bytes.to_vec()));
        Ok(())
    }

    /// Is `path` an `Active` entry of this key's current book? (SP10 §2: a path outside the
    /// book can never be signed for.)
    pub fn path_active(&self, key_id: &KeyId, path: &str) -> bool {
        self.books.get(key_id).is_some_and(|(b, _)| b.entries.iter().any(|e| e.path == path && e.status == AddressStatus::Active))
    }

    /// Find an entry across all keys' books: (entry, book bytes, key id, key version).
    pub fn find(&self, chain: &str, address: Option<&str>, path: Option<&str>) -> Option<(&AddressEntry, &[u8], KeyId, u32)> {
        self.books.values().find_map(|(b, bytes)| {
            b.entries
                .iter()
                .find(|e| e.chain == chain && address.is_none_or(|a| same_address(chain, &e.address, a)) && path.is_none_or(|p| e.path == p))
                .map(|e| (e, bytes.as_slice(), b.key_id, b.key_version))
        })
    }
}

/// Address equality: case-insensitive only for EVM hex addresses (base58/bech32 chains are
/// case-sensitive or canonical lower-case).
pub fn same_address(chain: &str, a: &str, b: &str) -> bool {
    if chain.starts_with("evm:") {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
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
    #[error("the proof answers a different address than the one asked")]
    WrongEntry,
}

/// What the requester asked (the proof must answer exactly this).
pub struct Asked<'a> {
    pub request_id: B32,
    pub nonce: B32,
    pub chain: &'a str,
    pub address: Option<&'a str>,
    pub path: Option<&'a str>,
}

/// Requester-side verification of an `AddressProof` (SP10 §4), in order. Needs only the pinned
/// roster (`trust`), the last accepted book version and the query. The entry must answer the
/// query (chain, address and/or path): a valid proof for *another* address is an alarm.
pub fn verify_proof(trust: &Trust, proof_frame: &[u8], asked: &Asked<'_>, last_book: u64, now: u64) -> Result<AddressEntry, ProofError> {
    let nonce = &asked.nonce;
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
    if p.nonce != *nonce || p.request_id != asked.request_id {
        return Err(ProofError::ProdSig);
    }
    // Only an authenticated answer can raise this alarm: the proof must answer the question.
    if p.entry.chain != asked.chain
        || asked.address.is_some_and(|a| !same_address(asked.chain, &p.entry.address, a))
        || asked.path.is_some_and(|x| p.entry.path != x)
        || (asked.address.is_none() && asked.path.is_none())
    {
        return Err(ProofError::WrongEntry);
    }
    Ok(p.entry)
}
