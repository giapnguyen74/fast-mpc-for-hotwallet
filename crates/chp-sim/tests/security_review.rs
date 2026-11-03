//! Regression tests for the security review findings (docs/SECURITY.md).

use chp_core::{digest::ssid, Event};
use chp_crypto::{derive::t_path, ecdsa::prod_fragment};
use chp_sim::*;
use chp_wire::{msgs::*, presig_id, Bytes, Fault, MsgType, B32};

const ETH: u128 = 1_000_000_000_000_000_000;

fn frozen(w: &World) -> Option<Fault> {
    w.cold.st.keyring.get(&w.key_id, 1).unwrap().frozen
}

/// A compromised PROD's job for `id`, with its own fragment over `raw`.
fn job_for(w: &mut World, env: &[u8], raw: &[u8], id: u64, prod_time: u64) -> (Job, Vec<chp_crypto::ecdsa::EcdsaFragment>) {
    let pool = w.pool(PATH);
    let half = w.prod.adversary_take_half(&pool, id).expect("half");
    let y = w.prod.keyring.get(&w.key_id, 1).unwrap().group_key();
    let m = chp_chain::decode(CHAIN, raw).unwrap().messages[0];
    let frag = prod_fragment(half, &m, &t_path(&w.key_id.0, &y, PATH)).unwrap();
    let job = Job {
        job_seq: w.prod.adversary_bump_job_seq(),
        envelope: Bytes(env.to_vec()),
        key_version: 1,
        items: vec![JobItem { input: 0, presig_id: id, ssid: ssid(CHAIN, &w.key_id, 1, id, &m, PATH) }],
        prod_time,
        sealed: Sealed { enc: Bytes::default(), ct: Bytes::default() },
    };
    (job, vec![frag])
}

#[tokio::test(flavor = "multi_thread")]
async fn a_withheld_unfreeze_cannot_lift_a_later_freeze() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 1).await;
    // incident 1
    w.cold.freeze(w.key_id, 1, Fault::FinalVerify, B32([1; 32]), None);
    w.pump().await;
    let u1 = w.unfreeze(); // names incident 1
    // the host withholds a copy of u1 … then incident 2 happens
    w.cold.freeze(w.key_id, 1, Fault::ProdFragment, B32([2; 32]), None);
    w.pump().await;
    // replaying u1 (even re-signed with a higher version for the old incident) does not lift it
    let stale = w.q.ceremony.sign(w.q.m, MsgType::Unfreeze, &UnfreezeBody { key_id: w.key_id, key_version: 1, version: 99, evidence_hash: B32([1; 32]) });
    assert!(w.cold.apply_quorum(&u1, w.now).is_err());
    assert!(w.cold.apply_quorum(&stale, w.now).is_err());
    assert_eq!(frozen(&w), Some(Fault::ProdFragment));
    // only an Unfreeze naming incident 2 works
    w.unfreeze();
    assert_eq!(frozen(&w), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn restoring_cold_control_state_fails_closed() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 2).await;
    // snapshot BEFORE a freeze, then the key is frozen (incident)
    let snap = w.cold.snapshot();
    w.cold.freeze(w.key_id, 1, Fault::FinalVerify, B32([7; 32]), None);
    assert!(frozen(&w).is_some());
    // attacker restores the pre-freeze storage and reboots COLD: the freeze would be gone …
    w.cold.restore_storage(&snap);
    assert!(frozen(&w).is_none(), "restored state has no freeze");
    w.cold.boot();
    // … but the state counter detects it: every key frozen (Rollback), every pool discarded
    assert_eq!(frozen(&w), Some(Fault::Rollback));
    assert!(w.cold.pool(&w.pool(PATH)).unwrap().halves.is_empty());
    w.prod.link_lost();
    w.connect_prod();
    w.pump().await;
    assert!(w.withdraw(DEST, 1, PATH).await.is_err() || w.broadcasts.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn fees_count_against_limits() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 1).await;
    // 1 wei to an allowlisted address, but max fee = 21000 · 10^15 wei/gas = 21 ETH
    let to: [u8; 20] = hex::decode(DEST.trim_start_matches("0x")).unwrap().try_into().unwrap();
    let raw = chp_chain::evm::Eip1559 { chain_id: 31337, nonce: 1, max_priority_fee: 10u128.pow(15), max_fee: 10u128.pow(15), gas_limit: 21_000, to, value: 1, data: vec![] }.encode_unsigned();
    let (_, env) = w.envelope(raw.clone(), PATH);
    let before = w.prod.available(&w.pool(PATH));
    let r = w.prod.withdraw(&env, w.now);
    assert!(r.unwrap_err().to_string().contains("fee"), "PROD refuses at admission");
    assert_eq!(w.prod.available(&w.pool(PATH)), before);
    // a compromised PROD forwards it anyway: COLD's own policy refuses
    let id = w.prod.held_ids(&w.pool(PATH))[0];
    let (job, frags) = { let now = w.now; job_for(&mut w, &env, &raw, id, now) };
    let seq = job.job_seq;
    w.prod.adversary_send_job(job, &frags);
    w.pump().await;
    let st = w.status_of(seq).unwrap();
    assert_eq!(st.outcome, Outcome::Rejected);
    assert!(st.reason.contains("fee"), "{}", st.reason);
    let _ = ETH;
}

#[tokio::test(flavor = "multi_thread")]
async fn prod_time_cannot_evict_cold_replay_cache() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 1).await;
    let raw1 = w.tx(DEST, 1);
    let (_, e1) = w.envelope(raw1.clone(), PATH);
    let t0 = w.now;
    w.prod.withdraw(&e1, t0).unwrap();
    w.pump().await;
    assert_eq!(w.broadcasts.len(), 1);
    // later, a second envelope with a PROD time pushed past E1's not_after (still within skew)
    w.advance(100);
    let raw2 = w.tx(DEST, 2);
    let (_, e2) = w.envelope(raw2.clone(), PATH);
    let id = w.prod.held_ids(&w.pool(PATH))[0];
    let (j2, f2) = job_for(&mut w, &e2, &raw2, id, t0 + 125);
    w.prod.adversary_send_job(j2, &f2);
    w.pump().await;
    // then E1 again under a fresh job_seq: must be refused as a replay
    let id = w.prod.held_ids(&w.pool(PATH))[0];
    let (j1, f1) = job_for(&mut w, &e1, &raw1, id, t0 + 100);
    let seq = j1.job_seq;
    w.prod.adversary_send_job(j1, &f1);
    w.pump().await;
    let st = w.status_of(seq).unwrap();
    assert_eq!(st.outcome, Outcome::Rejected, "{}", st.reason);
    assert!(st.reason.contains("replay"), "{}", st.reason);
}

#[tokio::test(flavor = "multi_thread")]
async fn forged_replica_bits_are_a_fault_and_do_not_brick_the_pool() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 1).await;
    let raw = w.tx(DEST, 1);
    let (_, env) = w.envelope(raw.clone(), PATH);
    let id = w.prod.held_ids(&w.pool(PATH))[0];
    let mark_before = w.cold.pool(&w.pool(PATH)).unwrap().high_water;
    let (mut job, frags) = { let now = w.now; job_for(&mut w, &env, &raw, id, now) };
    let forged = id | (0xffu64 << 56);
    assert_eq!(presig_id::block(forged), presig_id::block(id));
    job.items[0].presig_id = forged;
    let seq = job.job_seq;
    w.prod.adversary_send_job(job, &frags);
    w.pump().await;
    assert_eq!(w.status_of(seq).unwrap().outcome, Outcome::Fault(Fault::PresigState));
    assert_eq!(w.cold.pool(&w.pool(PATH)).unwrap().high_water, mark_before, "mark not pushed to ~2^64");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_hooks_events_do_not_leak_secrets() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 1).await;
    let halves = w.prod.steal_halves();
    let dbg = format!("{:?}", halves[0].2);
    assert!(dbg.contains("redacted"), "{dbg}");
    let _ = Event::Info(String::new());
}
