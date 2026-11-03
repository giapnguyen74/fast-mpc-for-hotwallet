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
    /// A presign fault happened on this version: its key shares' base-OT secrets may have been
    /// probed (selective-failure attack). Presign stays refused for this version for good, even
    /// after an Unfreeze; recovery is a refresh (fresh OT seeds) or a sweep to a new key.
    #[serde(default)]
    pub presign_tainted: bool,
}

impl KeyEntry {
    pub fn group_key(&self) -> ProjectivePoint {
        decode_point(&self.manifest.group_key.0).expect("validated at install")
    }
    pub fn usable(&self) -> bool {
        self.state == KeyState::Active && self.frozen.is_none()
    }

    /// May new presignatures be made for this version?
    pub fn presign_allowed(&self) -> bool {
        self.usable() && !self.presign_tainted
    }
}

pub fn decode_point(b: &[u8]) -> Option<ProjectivePoint> {
    let a: [u8; 33] = b.try_into().ok()?;
    chp_crypto::ecdsa::decode_point(&a).ok()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Keyring {
    keys: BTreeMap<(KeyId, u32), KeyEntry>,
    /// The fault and issue time of the freeze the last applied Unfreeze lifted.
    #[serde(default)]
    pub last_lifted: Option<(Fault, u64)>,
}

impl Keyring {
    /// Verify and record a quorum-signed `KeyManifest` (state `ActivePending`).
    /// Re-importing a recorded version is ignored (forward-only).
    pub fn install_manifest(&mut self, trust: &Trust, bytes: &[u8]) -> Result<&KeyEntry, KeyError> {
        let m: KeyManifest = trust.verify_quorum(bytes, MsgType::KeyManifest)?;
        if m.protocol == Protocol::Dkls23Secp256k1 && decode_point(&m.group_key.0).is_none() {
            return Err(KeyError::BadManifest("group key"));
        }
        // A new version of an existing key (refresh) must keep the same group key, protocol and
        // chain: a quorum cannot swap in another key under an existing key_id (deep review C1).
        if let Some(other) = self.keys.iter().find(|((id, v), _)| *id == m.key_id && *v != m.key_version).map(|(_, e)| e) {
            if other.manifest.group_key != m.group_key || other.manifest.protocol != m.protocol || other.manifest.chain != m.chain {
                return Err(KeyError::BadManifest("a new version must keep the key's group key, protocol and chain"));
            }
        }
        let k = (m.key_id, m.key_version);
        if let Some(existing) = self.keys.get(&k) {
            if existing.manifest != m {
                return Err(KeyError::BadManifest("a different manifest for an installed key version"));
            }
        }
        self.keys.entry(k).or_insert(KeyEntry {
            manifest: m,
            manifest_bytes: bytes.to_vec(),
            manifest_hash: hash_of(bytes),
            state: KeyState::ActivePending,
            frozen: None,
            freeze_evidence: None,
            presign_tainted: false,
        });
        Ok(&self.keys[&k])
    }

    pub fn get(&self, key_id: &KeyId, version: u32) -> Option<&KeyEntry> {
        self.keys.get(&(*key_id, version))
    }

    /// The highest non-retired version of a key.
    /// The highest **Active** version of a key (a pending manifest — public data any host can
    /// feed — must not stop signing with the current version; security review round 2).
    pub fn current(&self, key_id: &KeyId) -> Option<&KeyEntry> {
        self.keys.iter().filter(|((k, _), e)| k == key_id && e.state == KeyState::Active).map(|(_, e)| e).next_back()
    }

    /// Any non-retired version of a key (pending or active), for installing per-key data.
    pub fn known(&self, key_id: &KeyId) -> bool {
        self.keys.iter().any(|((k, _), e)| k == key_id && e.state != KeyState::Retired)
    }

    pub fn all(&self) -> impl Iterator<Item = &KeyEntry> {
        self.keys.values()
    }

    /// Verify a control object and check the transition **before** consuming its version
    /// (rule 1: a refusal changes no state).
    fn control(&mut self, trust: &mut Trust, bytes: &[u8], t: MsgType) -> Result<KeyControl, KeyError> {
        let c: KeyControl = trust.verify_quorum(bytes, t)?;
        let e = self.keys.get(&(c.key_id, c.key_version)).ok_or(KeyError::Unknown)?;
        if t == MsgType::Activate && e.state == KeyState::Retired {
            return Err(KeyError::Transition("retired → active"));
        }
        trust.bump_version(&format!("{t:?}/{}", hex::encode(c.key_id.0)), c.version)?;
        Ok(c)
    }

    /// Quorum `Activate` (SP3 §4 step 5): `ActivePending → Active`.
    pub fn apply_activate(&mut self, trust: &mut Trust, bytes: &[u8]) -> Result<KeyControl, KeyError> {
        let c = self.control(trust, bytes, MsgType::Activate)?;
        let e = self.keys.get_mut(&(c.key_id, c.key_version)).unwrap();
        if e.state == KeyState::ActivePending {
            e.state = KeyState::Active;
        }
        Ok(c)
    }

    /// Quorum `Retire` (SP8 §2): the version becomes unusable. Nothing is deleted (rule 8).
    pub fn apply_retire(&mut self, trust: &mut Trust, bytes: &[u8]) -> Result<KeyControl, KeyError> {
        let c = self.control(trust, bytes, MsgType::Retire)?;
        self.keys.get_mut(&(c.key_id, c.key_version)).unwrap().state = KeyState::Retired;
        Ok(c)
    }

    /// Quorum `Unfreeze` (SP7 §3). It must name the evidence of the freeze in force (it may name
    /// several, for parties that froze on different evidence), so an Unfreeze issued for one
    /// incident cannot lift a later freeze. Refused, consuming nothing, if the key is not frozen.
    pub fn apply_unfreeze(&mut self, trust: &mut Trust, bytes: &[u8]) -> Result<KeyControl, KeyError> {
        let u: UnfreezeBody = trust.verify_quorum(bytes, MsgType::Unfreeze)?;
        let e = self.keys.get(&(u.key_id, u.key_version)).ok_or(KeyError::Unknown)?;
        let Some(ev) = e.freeze_evidence else { return Err(KeyError::Transition("key is not frozen")) };
        if !u.evidence.contains(&ev) {
            return Err(KeyError::Transition("Unfreeze names another freeze"));
        }
        trust.bump_version(&format!("Unfreeze/{}", hex::encode(u.key_id.0)), u.version)?;
        let e = self.keys.get_mut(&(u.key_id, u.key_version)).unwrap();
        self.last_lifted = e.frozen.map(|f| (f, u.issued_at));
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

    /// Mark a version presign-tainted (permanent for this version).
    pub fn taint_presign(&mut self, key_id: &KeyId, version: u32) {
        if let Some(e) = self.keys.get_mut(&(*key_id, version)) {
            e.presign_tainted = true;
        }
    }

    /// Fail closed after a detected storage restore: **overwrite** every key's freeze with this
    /// fault and evidence, including keys already frozen in the restored state, so no Unfreeze
    /// minted before the restore can lift it (security review round 2). Returns the keys.
    pub fn force_freeze_all(&mut self, fault: Fault, evidence: chp_wire::B32) -> Vec<(KeyId, u32)> {
        let mut out = Vec::new();
        for ((k, v), e) in self.keys.iter_mut() {
            if e.state == KeyState::Retired {
                continue;
            }
            e.frozen = Some(fault);
            e.freeze_evidence = Some(evidence);
            out.push((*k, *v));
        }
        out
    }
}
