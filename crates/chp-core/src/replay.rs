//! Seen-before cache for API requests (`request_id`, query `nonce`), pruned after `not_after`.
//!
//! Safety rule: an entry is pruned only when the caller's *prune clock* has passed its expiry,
//! and the caller checks request expiry against a clock that is never below that prune clock.
//! Then a pruned request is always already expired, and a replay is refused either as a
//! duplicate or as expired, however the request is dated. COLD prunes with its authenticated,
//! monotonic time floor (never the host clock); there is deliberately no lifetime cap (a cap
//! below `not_after` is what reopened double signing in security review round 2).

use std::collections::BTreeMap;

use chp_wire::B32;
use serde::{Deserialize, Serialize};

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ReplayCache {
    seen: BTreeMap<B32, u64>,
}

impl ReplayCache {
    /// Returns `false` if `id` was seen before. Records it until `expires`; prunes entries whose
    /// expiry is below `prune_clock` (see the module safety rule).
    pub fn check_and_insert(&mut self, id: B32, expires: u64, prune_clock: u64) -> bool {
        self.seen.retain(|_, exp| *exp >= prune_clock);
        let not_after = expires;
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
