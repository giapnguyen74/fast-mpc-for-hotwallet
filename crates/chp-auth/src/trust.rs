//! Trust roots, rosters, certificates, revocation and anti-rollback (DESIGN SP1 §2, §3, §7, §8).

use std::collections::{BTreeMap, BTreeSet};

use chp_crypto::ident;
use chp_wire::{
    decode_canonical,
    msgs::{PartyCert, PolicyBundle, RevocationList, Roster},
    MsgType, QuorumRole, QuorumSignedMsg, Role, B32,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::{quorum::quorum_digest, AuthError, Result};

/// Roots compiled into each enclave image (DESIGN SP1 §2).
#[derive(Clone, Debug)]
pub struct Pinned {
    pub rosters: Vec<Roster>,
    /// Allowed enclave measurements (the signed release list).
    pub releases: Vec<B32>,
}

/// A party's current view of the trust roots. Serializable: it is part of a party's sealed,
/// rollback-protected state.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Trust {
    releases: BTreeSet<B32>,
    rosters: BTreeMap<QuorumRole, Roster>,
    revoked: BTreeSet<B32>,
    /// Role of each revoked key (as named by the quorum).
    revocation_ver: u64,
    versions: BTreeMap<String, u64>,
}

/// Which quorum signs a type (with fallback to the ceremony quorum when quorum separation is
/// not configured, DESIGN SP1 §2).
pub fn quorum_role_for(t: MsgType, policy_target: Option<Role>) -> QuorumRole {
    match t {
        MsgType::Unfreeze => QuorumRole::Incident,
        MsgType::RevocationList => QuorumRole::Revocation,
        MsgType::PolicyBundle => match policy_target {
            Some(Role::Cold) => QuorumRole::PolicyCold,
            _ => QuorumRole::PolicyProd,
        },
        _ => QuorumRole::Ceremony,
    }
}

/// Types that only a quorum may sign.
pub fn is_quorum_type(t: MsgType) -> bool {
    use MsgType::*;
    matches!(
        t,
        PartyCert | RosterUpdate | RevocationList | CeremonyOpen | KeyManifest | SharePackage | Activate
            | Retire | Unfreeze | PolicyBundle | QrPairing | AddressBook
    )
}

impl Trust {
    pub fn new(p: &Pinned) -> Self {
        Trust {
            releases: p.releases.iter().copied().collect(),
            rosters: p.rosters.iter().map(|r| (r.role, r.clone())).collect(),
            revoked: BTreeSet::new(),
            revocation_ver: 0,
            versions: BTreeMap::new(),
        }
    }

    pub fn revocation_ver(&self) -> u64 {
        self.revocation_ver
    }

    pub fn roster(&self, role: QuorumRole) -> Option<&Roster> {
        self.rosters.get(&role).or(match role {
            QuorumRole::Incident | QuorumRole::Revocation => self.rosters.get(&QuorumRole::Ceremony),
            _ => None,
        })
    }

    fn check_sigs(&self, q: &QuorumSignedMsg, role: QuorumRole) -> Result<()> {
        let roster = self.roster(role).ok_or_else(|| AuthError::Quorum(format!("no roster for {role:?}")))?;
        // Bound the work before verifying anything: at most one signature per roster member,
        // no duplicates, and stop at the threshold (deep review: padding cost CPU).
        if q.sigs.len() > roster.members.len() {
            return Err(AuthError::Quorum("more signatures than roster members".into()));
        }
        let distinct: BTreeSet<B32> = q.sigs.iter().map(|s| s.member).collect();
        if distinct.len() != q.sigs.len() {
            return Err(AuthError::Quorum("duplicate signer".into()));
        }
        let d = quorum_digest(q.msg_type, &q.body.0);
        let mut seen = BTreeSet::new();
        for s in &q.sigs {
            if seen.len() >= roster.threshold as usize && roster.threshold > 0 {
                break;
            }
            // Non-members and duplicate signers are ignored (SP1 §7).
            // Revoked members do not count (security review: a RevocationList may name a
            // custodian before the next RosterUpdate).
            if !roster.members.contains(&s.member) || seen.contains(&s.member) || self.revoked.contains(&B32(ident::key_hash(&s.member.0))) {
                continue;
            }
            if ident::verify(&s.member.0, &d, &s.sig.0).is_ok() {
                seen.insert(s.member);
            }
        }
        if seen.len() >= roster.threshold as usize && roster.threshold > 0 {
            Ok(())
        } else {
            Err(AuthError::Quorum(format!("{} valid signatures, need {}", seen.len(), roster.threshold)))
        }
    }

    /// Verify a `QuorumSignedMsg` of type `want` and return its canonical body.
    pub fn verify_quorum<T: DeserializeOwned + Serialize>(&self, bytes: &[u8], want: MsgType) -> Result<T> {
        let q: QuorumSignedMsg = decode_canonical(bytes).map_err(AuthError::Frame)?;
        let t = MsgType::from_code(q.msg_type).ok_or(AuthError::UnknownType(q.msg_type))?;
        if t != want {
            return Err(AuthError::WrongType { want, got: t });
        }
        if !is_quorum_type(t) {
            return Err(AuthError::Quorum(format!("{t:?} is not a quorum type")));
        }
        let body: T = decode_canonical(&q.body.0).map_err(AuthError::Body)?;
        let target = if t == MsgType::PolicyBundle {
            let pb: PolicyBundle = decode_canonical(&q.body.0).map_err(AuthError::Body)?;
            Some(pb.target)
        } else {
            None
        };
        self.check_sigs(&q, quorum_role_for(t, target))?;
        Ok(body)
    }

    /// Anti-rollback: accept `v` for `slot` only if strictly above the last accepted (SP1 §7).
    pub fn bump_version(&mut self, slot: &str, v: u64) -> Result<()> {
        let last = *self.versions.get(slot).unwrap_or(&0);
        if v <= last {
            return Err(AuthError::Rollback { got: v, last });
        }
        self.versions.insert(slot.to_string(), v);
        Ok(())
    }

    pub fn version(&self, slot: &str) -> u64 {
        *self.versions.get(slot).unwrap_or(&0)
    }

    /// Apply a `RosterUpdate` signed by the current roster of that role (SP1 §2).
    pub fn apply_roster_update(&mut self, bytes: &[u8]) -> Result<bool> {
        let q: QuorumSignedMsg = decode_canonical(bytes).map_err(AuthError::Frame)?;
        if q.msg_type != MsgType::RosterUpdate.code() {
            return Err(AuthError::WrongType { want: MsgType::RosterUpdate, got: MsgType::from_code(q.msg_type).unwrap_or(MsgType::RosterUpdate) });
        }
        let r: Roster = decode_canonical(&q.body.0).map_err(AuthError::Body)?;
        let cur = self.rosters.get(&r.role).ok_or_else(|| AuthError::Quorum("unknown roster role".into()))?;
        if r.version <= cur.version {
            return Ok(false); // already have it (or older): ignored
        }
        self.check_sigs(&q, r.role)?;
        let distinct: BTreeSet<B32> = r.members.iter().copied().collect();
        if r.threshold == 0 || (r.threshold as usize) > r.members.len() || distinct.len() != r.members.len() {
            return Err(AuthError::Quorum("bad threshold or duplicate members".into()));
        }
        self.rosters.insert(r.role, r);
        Ok(true)
    }

    /// Apply a quorum `RevocationList` (SP1 §8). Returns the newly revoked entries.
    pub fn apply_revocation(&mut self, bytes: &[u8]) -> Result<Vec<chp_wire::msgs::Revoked>> {
        let rl: RevocationList = self.verify_quorum(bytes, MsgType::RevocationList)?;
        if rl.version <= self.revocation_ver {
            return Err(AuthError::Rollback { got: rl.version, last: self.revocation_ver });
        }
        self.revocation_ver = rl.version;
        let new: Vec<_> = rl.revoked.iter().filter(|k| !self.revoked.contains(&k.key_hash)).cloned().collect();
        self.revoked.extend(rl.revoked.iter().map(|r| r.key_hash));
        Ok(new)
    }

    pub fn is_revoked(&self, id_pk_hash: &B32) -> bool {
        self.revoked.contains(id_pk_hash)
    }

    /// Verify a quorum-signed `PartyCert` (SP1 §3): quorum, validity window, measurement on the
    /// release list, not revoked. Returns the certificate and `SHA-256(cert bytes)`.
    pub fn verify_cert(&self, bytes: &[u8], now: u64) -> Result<(PartyCert, B32)> {
        let c: PartyCert = self.verify_quorum(bytes, MsgType::PartyCert)?;
        if now < c.not_before || now > c.not_after {
            return Err(AuthError::Cert("outside validity window".into()));
        }
        // Clients (UPSTREAM, requesters) run outside enclaves in this prototype: their
        // measurement is not checked against the enclave release list.
        if matches!(c.role, Role::Hot | Role::Cold | Role::Prod | Role::Rec) && !self.releases.contains(&c.measurement) {
            return Err(AuthError::Cert("measurement not on release list".into()));
        }
        if self.is_revoked(&B32(ident::key_hash(&c.id_pk.0))) {
            return Err(AuthError::Revoked);
        }
        // Enclave parties must have a usable HPKE wrap key (a small-order key crashed HOT's
        // export; deep review): probe it once.
        if matches!(c.role, Role::Hot | Role::Cold | Role::Prod | Role::Rec)
            && chp_crypto::seal::seal(&c.wrap_pk.0, b"chp-wrap-probe", &[], &[], &mut rand::thread_rng()).is_err()
        {
            return Err(AuthError::Cert("unusable wrap key".into()));
        }
        Ok((c, B32(chp_crypto::hash::sha256(bytes))))
    }
}
