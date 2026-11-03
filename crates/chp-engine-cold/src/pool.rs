//! COLD's per-pool presignature state (DESIGN SP4 §4, SP6 step 4, §6.1).
//!
//! A pool is `(key_id, key_version, path)`. Each pool has its own id sequence, its own
//! high-water mark and its own hardware monotonic counter holding the pool's current block.
//! Ids: `hot_replica ‖ cold_replica ‖ block ‖ index`, one block per batch.

use std::collections::{BTreeMap, BTreeSet};

use chp_crypto::ecdsa::EcdsaHalf;
use chp_wire::{presig_id, PoolId, PresigId, B32};
use serde::{Deserialize, Serialize};

/// Sealed (restorable) state of one pool.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Pool {
    /// Next block to allocate for a batch (always above the hardware counter).
    pub next_block: u32,
    /// Issued blocks → (batch, number of ids).
    pub issued: BTreeMap<u32, (B32, u16)>,
    /// COLD's halves (pending or active) by id.
    pub halves: BTreeMap<PresigId, EcdsaHalf>,
    /// Ids whose batch is not yet active.
    pub pending: BTreeSet<PresigId>,
    /// Issued ids whose half is gone (aborted, orphan-deleted, burned): ordinary, not a fault.
    pub gone: BTreeSet<PresigId>,
    pub high_water: PresigId,
    /// Discard floor: every id in a block `<= floor_block` is refused.
    pub floor_block: Option<u32>,
    /// The counter value COLD itself last set (sealed with the state; restore detection).
    pub last_set_counter: u64,
}

/// How COLD classifies one named presignature id in a job (DESIGN SP6 step 4.3).
#[derive(Debug, PartialEq, Eq)]
pub enum IdClass {
    /// Usable: the half was taken (deleted from the pool).
    Take,
    /// Burned on both sides, job `REJECTED`, not a fault.
    Reject(&'static str),
    /// `FAULT_PRESIG_STATE`: the key freezes.
    Fault(&'static str),
}

impl Pool {
    pub fn counter_name(p: &PoolId) -> String {
        format!("pool/{}/{}/{}", hex::encode(p.key_id.0), p.key_version, p.path)
    }

    pub fn issued_id(&self, id: PresigId) -> bool {
        let b = presig_id::block(id);
        self.issued.get(&b).is_some_and(|(_, n)| (presig_id::index(id) as u32) < *n as u32)
    }

    /// Classify one id against the pool state and the hardware counter value `hw`.
    pub fn classify(&self, id: PresigId, hw: u64) -> IdClass {
        let b = presig_id::block(id);
        if !self.issued_id(id) {
            return IdClass::Fault("presig id never issued");
        }
        if self.floor_block.is_some_and(|f| b <= f) {
            return IdClass::Reject("id below a discarded pool's floor");
        }
        if (b as u64) < hw {
            return IdClass::Reject("id in a closed block");
        }
        if id <= self.high_water {
            // inside the current open block (b >= hw) and at or below the mark: replay
            return IdClass::Fault("id at or below the high-water mark in the open block");
        }
        if self.gone.contains(&id) || !self.halves.contains_key(&id) {
            return IdClass::Reject("half already deleted (aborted / orphan)");
        }
        if self.pending.contains(&id) {
            return IdClass::Reject("batch not active");
        }
        IdClass::Take
    }

    /// Advance the mark to `id` and delete the named half and every lower one ("skipped ids
    /// are burned"). Returns the taken half if present.
    pub fn take_up_to(&mut self, id: PresigId) -> Option<EcdsaHalf> {
        if id > self.high_water {
            self.high_water = id;
        }
        let lower: Vec<PresigId> = self.halves.range(..=id).map(|(k, _)| *k).collect();
        let mut taken = None;
        for k in lower {
            let h = self.halves.remove(&k);
            self.pending.remove(&k);
            self.gone.insert(k);
            if k == id {
                taken = h;
            }
        }
        taken
    }

    /// Delete every half in blocks `< up_to_block` (closed blocks) and return the deleted ids.
    pub fn delete_below_block(&mut self, up_to_block: u32) -> Vec<PresigId> {
        let ids: Vec<PresigId> = self.halves.keys().copied().filter(|i| presig_id::block(*i) < up_to_block).collect();
        for i in &ids {
            self.halves.remove(i);
            self.pending.remove(i);
            self.gone.insert(*i);
        }
        ids
    }

    /// Discard the pool (restore detected, revocation, retire): delete every half, set the floor.
    pub fn discard(&mut self, floor: u32) {
        let all: Vec<PresigId> = self.halves.keys().copied().collect();
        for i in all {
            self.halves.remove(&i);
            self.gone.insert(i);
        }
        self.pending.clear();
        let f = self.issued.keys().last().copied().unwrap_or(0).max(floor);
        self.floor_block = Some(f);
        self.next_block = self.next_block.max(f + 1);
    }

    pub fn active_ids(&self) -> Vec<PresigId> {
        self.halves.keys().copied().filter(|i| !self.pending.contains(i)).collect()
    }
}
