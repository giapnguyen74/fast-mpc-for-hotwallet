//! Seen-before cache for API requests (`request_id`, query `nonce`), pruned after `not_after`.

use std::collections::BTreeMap;

use chp_wire::B32;
use serde::{Deserialize, Serialize};

/// Requests are valid at most 300 s (DESIGN SP6 step 2); keep entries a little longer.
pub const MAX_TTL: u64 = 600;

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ReplayCache {
    seen: BTreeMap<B32, u64>,
}

impl ReplayCache {
    /// Returns `false` if `id` was seen before. Records it until `not_after`, capped at
    /// `now + MAX_TTL` of the **caller's own clock** (callers must not pass peer-chosen time).
    pub fn check_and_insert(&mut self, id: B32, not_after: u64, now: u64) -> bool {
        self.seen.retain(|_, exp| *exp >= now);
        let not_after = not_after.min(now + MAX_TTL);
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
