//! Seen-before cache for API requests (`request_id`, query `nonce`), pruned after `not_after`.

use std::collections::BTreeMap;

use chp_wire::B32;
use serde::{Deserialize, Serialize};

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ReplayCache {
    seen: BTreeMap<B32, u64>,
}

impl ReplayCache {
    /// Returns `false` if `id` was seen before. Records it until `not_after`.
    pub fn check_and_insert(&mut self, id: B32, not_after: u64, now: u64) -> bool {
        self.seen.retain(|_, exp| *exp >= now);
        if self.seen.contains_key(&id) {
            return false;
        }
        self.seen.insert(id, not_after);
        true
    }
    pub fn contains(&self, id: &B32) -> bool {
        self.seen.contains_key(id)
    }
}
