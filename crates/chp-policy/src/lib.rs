//! Reference policy engine (DESIGN SP7 §4).
//!
//! Policy *content* is the deployer's choice; the protocol requires two independent
//! validations from two independent sources. Each of PROD and COLD holds its own
//! [`PolicyState`]: its own quorum-signed rules (bundle `target` = itself) and its own ledger,
//! evaluated on its **own decode** of the transaction.

use std::collections::BTreeMap;

use chp_chain::Decoded;
use chp_wire::msgs::PolicyRules;
use serde::{Deserialize, Serialize};

const DAY: u64 = 86_400;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Approve,
    Reject(String),
}

/// Rules in force plus this party's own ledger.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PolicyState {
    pub version: u64,
    pub rules: PolicyRules,
    /// (time, value + max fee) of every signed withdrawal in the last 24 h (rolling window;
    /// counted when signed, DESIGN §10.5).
    ledger: BTreeMap<u64, u128>,
}

fn parse(s: &str) -> u128 {
    s.parse().unwrap_or(0)
}

impl PolicyState {
    pub fn install(&mut self, version: u64, rules: PolicyRules) {
        self.version = version;
        self.rules = rules;
    }

    /// Evaluate a decoded withdrawal. No state change.
    pub fn evaluate(&self, d: &Decoded, now: u64) -> Verdict {
        let r = &self.rules;
        if self.version == 0 {
            return Verdict::Reject("no policy installed".into());
        }
        if !r.chain_ids.contains(&d.chain_id) {
            return Verdict::Reject(format!("chain id {} not allowed", d.chain_id));
        }
        if d.has_calldata && !r.allow_calldata {
            return Verdict::Reject("contract calls not allowed".into());
        }
        if !r.allowlist.iter().any(|a| a.eq_ignore_ascii_case(&d.to)) {
            return Verdict::Reject(format!("destination {} not on allowlist", d.to));
        }
        if d.max_fee > parse(&r.max_fee_per_tx) {
            return Verdict::Reject("over per-transaction fee cap".into());
        }
        let cost = d.value.saturating_add(d.max_fee);
        if cost > parse(&r.max_per_tx) {
            return Verdict::Reject("over per-transaction limit (value + max fee)".into());
        }
        if self.spent_24h(now).saturating_add(cost) > parse(&r.max_per_day) {
            return Verdict::Reject("over rolling 24 h limit".into());
        }
        Verdict::Approve
    }

    fn spent_24h(&self, now: u64) -> u128 {
        self.ledger.range(now.saturating_sub(DAY - 1)..).map(|(_, v)| *v).fold(0u128, |a, v| a.saturating_add(v))
    }

    /// Record a signed withdrawal (value + max fee) in this party's ledger.
    pub fn record(&mut self, d: &Decoded, now: u64) {
        let e = self.ledger.entry(now).or_insert(0);
        *e = e.saturating_add(d.value.saturating_add(d.max_fee));
        self.ledger = self.ledger.split_off(&now.saturating_sub(DAY));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st() -> PolicyState {
        let mut p = PolicyState::default();
        p.install(1, PolicyRules {
            max_per_tx: "100".into(),
            max_per_day: "150".into(),
            allowlist: vec!["0xaa".into()],
            chain_ids: vec![1],
            allow_calldata: false,
            max_fee_per_tx: "10".into(),
        });
        p
    }
    fn d(to: &str, v: u128) -> Decoded {
        Decoded { messages: vec![[0; 32]], to: to.into(), value: v, chain_id: 1, has_calldata: false, max_fee: 0 }
    }

    #[test]
    fn limits_allowlist_and_ledger() {
        let mut p = st();
        assert_eq!(p.evaluate(&d("0xAA", 100), 0), Verdict::Approve);
        assert!(matches!(p.evaluate(&d("0xbb", 1), 0), Verdict::Reject(_)));
        assert!(matches!(p.evaluate(&d("0xaa", 101), 0), Verdict::Reject(_)));
        p.record(&d("0xaa", 100), 0);
        assert!(matches!(p.evaluate(&d("0xaa", 60), 10), Verdict::Reject(_)));
        // rolling window: still refused just after midnight, allowed 24 h after the spend
        assert!(matches!(p.evaluate(&d("0xaa", 60), DAY - 1), Verdict::Reject(_)));
        assert_eq!(p.evaluate(&d("0xaa", 60), DAY + 1), Verdict::Approve);
        let mut c = d("0xaa", 1);
        c.has_calldata = true; // zero-value approve() style call
        assert!(matches!(p.evaluate(&c, 0), Verdict::Reject(_)));
        // fees move funds too: a huge fee is refused even with a tiny value
        let mut f = d("0xaa", 1);
        f.max_fee = 11;
        assert!(matches!(p.evaluate(&f, 2 * DAY), Verdict::Reject(_)));
        // value + fee counts against the per-tx limit
        let mut g = d("0xaa", 95);
        g.max_fee = 10;
        assert!(matches!(p.evaluate(&g, 3 * DAY), Verdict::Reject(_)));
    }

    #[test]
    fn no_policy_rejects() {
        assert!(matches!(PolicyState::default().evaluate(&d("0xaa", 1), 0), Verdict::Reject(_)));
    }
}
