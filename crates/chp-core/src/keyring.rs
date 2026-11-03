//! Key manifests, key states and freezes (DESIGN SP3 §3, SP7, SP8).
//!
//! Forward-only: `ActivePending → Active → Retired`. A freeze is orthogonal and is lifted only
//! by a quorum `Unfreeze` with a higher version.

use std::collections::BTreeMap;

use chp_auth::{trust::Trust, AuthError};
use chp_wire::{
    msgs::{KeyControl, KeyManifest, UnfreezeBody},
    Fault, KeyId, KeyState, MsgType, Protocol,
};
use k256::ProjectivePoint;
use serde::{Deserialize, Serialize};

use crate::digest::hash_of;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("auth: {0}")]
    Auth(#[from] AuthError),
    #[error("unknown key version")]
    Unknown,
    #[error("bad manifest: {0}")]
    BadManifest(&'static str),
    #[error("illegal transition {0}")]
    Transition(&'static str),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyEntry {
    pub manifest: KeyManifest,
    pub manifest_bytes: Vec<u8>,
    pub manifest_hash: chp_wire::B32,
    pub state: KeyState,
    pub frozen: Option<Fault>,
    /// Evidence of the freeze in force; an `Unfreeze` must name it.
    pub freeze_evidence: Option<chp_wire::B32>,
}

impl KeyEntry {
    pub fn group_key(&self) -> ProjectivePoint {
        decode_point(&self.manifest.group_key.0).expect("validated at install")
    }
    pub fn usable(&self) -> bool {
        self.state == KeyState::Active && self.frozen.is_none()
    }
}

pub fn decode_point(b: &[u8]) -> Option<ProjectivePoint> {
    let a: [u8; 33] = b.try_into().ok()?;
    chp_crypto::ecdsa::decode_point(&a).ok()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Keyring {
    keys: BTreeMap<(KeyId, u32), KeyEntry>,
}

impl Keyring {
    /// Verify and record a quorum-signed `KeyManifest` (state `ActivePending`).
    /// Re-importing a recorded version is ignored (forward-only).
    pub fn install_manifest(&mut self, trust: &Trust, bytes: &[u8]) -> Result<&KeyEntry, KeyError> {
        let m: KeyManifest = trust.verify_quorum(bytes, MsgType::KeyManifest)?;
        if m.protocol == Protocol::Dkls23Secp256k1 && decode_point(&m.group_key.0).is_none() {
            return Err(KeyError::BadManifest("group key"));
        }
        let k = (m.key_id, m.key_version);
        self.keys.entry(k).or_insert(KeyEntry {
            manifest: m,
            manifest_bytes: bytes.to_vec(),
            manifest_hash: hash_of(bytes),
            state: KeyState::ActivePending,
            frozen: None,
            freeze_evidence: None,
        });
        Ok(&self.keys[&k])
    }

    pub fn get(&self, key_id: &KeyId, version: u32) -> Option<&KeyEntry> {
        self.keys.get(&(*key_id, version))
    }

    /// The highest non-retired version of a key.
    pub fn current(&self, key_id: &KeyId) -> Option<&KeyEntry> {
        self.keys.iter().filter(|((k, _), e)| k == key_id && e.state != KeyState::Retired).map(|(_, e)| e).next_back()
    }

    pub fn all(&self) -> impl Iterator<Item = &KeyEntry> {
        self.keys.values()
    }

    fn control(&mut self, trust: &mut Trust, bytes: &[u8], t: MsgType) -> Result<KeyControl, KeyError> {
        let c: KeyControl = trust.verify_quorum(bytes, t)?;
        if !self.keys.contains_key(&(c.key_id, c.key_version)) {
            return Err(KeyError::Unknown);
        }
        trust.bump_version(&format!("{t:?}/{}", hex::encode(c.key_id.0)), c.version)?;
        Ok(c)
    }

    /// Quorum `Activate` (SP3 §4 step 5): `ActivePending → Active`.
    pub fn apply_activate(&mut self, trust: &mut Trust, bytes: &[u8]) -> Result<KeyControl, KeyError> {
        let c = self.control(trust, bytes, MsgType::Activate)?;
        let e = self.keys.get_mut(&(c.key_id, c.key_version)).unwrap();
        match e.state {
            KeyState::ActivePending => e.state = KeyState::Active,
            KeyState::Active => {}
            KeyState::Retired => return Err(KeyError::Transition("retired → active")),
        }
        Ok(c)
    }

    /// Quorum `Retire` (SP8 §2): the version becomes unusable. Nothing is deleted (rule 8).
    pub fn apply_retire(&mut self, trust: &mut Trust, bytes: &[u8]) -> Result<KeyControl, KeyError> {
        let c = self.control(trust, bytes, MsgType::Retire)?;
        self.keys.get_mut(&(c.key_id, c.key_version)).unwrap().state = KeyState::Retired;
        Ok(c)
    }

    /// Quorum `Unfreeze` (SP7 §3). It must name the evidence of the freeze in force, so an
    /// Unfreeze issued for one incident cannot lift a later freeze.
    pub fn apply_unfreeze(&mut self, trust: &mut Trust, bytes: &[u8]) -> Result<KeyControl, KeyError> {
        let u: UnfreezeBody = trust.verify_quorum(bytes, MsgType::Unfreeze)?;
        let e = self.keys.get(&(u.key_id, u.key_version)).ok_or(KeyError::Unknown)?;
        if e.frozen.is_some() && e.freeze_evidence != Some(u.evidence_hash) {
            return Err(KeyError::Transition("Unfreeze names another freeze"));
        }
        trust.bump_version(&format!("Unfreeze/{}", hex::encode(u.key_id.0)), u.version)?;
        let e = self.keys.get_mut(&(u.key_id, u.key_version)).unwrap();
        e.frozen = None;
        e.freeze_evidence = None;
        Ok(KeyControl { key_id: u.key_id, key_version: u.key_version, version: u.version })
    }

    /// Freeze locally on own evidence or on a peer's `FreezeNotice`. Idempotent: the first
    /// freeze's evidence stays in force.
    pub fn freeze(&mut self, key_id: &KeyId, version: u32, fault: Fault, evidence: chp_wire::B32) -> bool {
        match self.keys.get_mut(&(*key_id, version)) {
            Some(e) if e.frozen.is_none() => {
                e.frozen = Some(fault);
                e.freeze_evidence = Some(evidence);
                true
            }
            _ => false,
        }
    }

    /// Freeze every key (fail closed, e.g. after a detected storage restore).
    pub fn freeze_all(&mut self, fault: Fault, evidence: chp_wire::B32) {
        let ks: Vec<(KeyId, u32)> = self.keys.keys().copied().collect();
        for (k, v) in ks {
            self.freeze(&k, v, fault, evidence);
        }
    }
}
