//! Reproducers from the deep review's randomised invariant testing (round 3), kept as
//! regression tests: each failed on the code before its fix.
//! Minimal reproducers for fuzzer findings.
use chp_core::{digest::ssid, Event};
use chp_crypto::{derive::t_path, ecdsa::prod_fragment};
use chp_sim::*;
use chp_wire::{msgs::*, Bytes, Role};

const ETH: u128 = 1_000_000_000_000_000_000;

fn signed(w: &World) -> Vec<chp_wire::B32> {
    w.cold.events.iter().filter_map(|e| if let Event::Signed { request_id, .. } = e { Some(*request_id) } else { None }).collect()
}

/// R-A: after a *detected* COLD storage restore and the quorum Unfreeze that names it, COLD
/// signs the same UPSTREAM request a second time (replay cache rolled back with the storage).
#[tokio::test(flavor = "multi_thread")]
async fn restore_then_unfreeze_resigns_same_request() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 1).await;
    let snap = w.cold.snapshot();                    // malicious host keeps an old image
    let raw = w.tx(DEST, ETH);
    let (rid, env) = w.envelope(raw.clone(), PATH);
    w.prod.withdraw(&env, w.now).unwrap();
    w.pump().await;
    assert_eq!(signed(&w), vec![rid]);
    // host restores the image and reboots COLD: detected, every key frozen (Rollback)
    w.cold.restore_storage(&snap);
    w.cold.boot();
    w.prod.link_lost();
    w.connect_prod();
    w.pump().await;
    // incident quorum follows the runbook: Unfreeze naming the rollback evidence
    w.unfreeze();
    // fresh presignatures (a normal refill) ...
    w.refill(PATH, 1).await;
    // ... and a compromised PROD replays UPSTREAM's already-signed envelope (still valid)
    let pool = w.pool(PATH);
    let id = w.prod.held_ids(&pool)[0];
    let half = w.prod.adversary_take_half(&pool, id).unwrap();
    let y = w.prod.keyring.get(&w.key_id, 1).unwrap().group_key();
    let m = chp_chain::decode(CHAIN, &raw).unwrap().messages[0];
    let frag = prod_fragment(half, &m, &t_path(&w.key_id.0, &y, PATH)).unwrap();
    let job = Job {
        job_seq: w.prod.adversary_bump_job_seq(),
        envelope: Bytes(env),
        key_version: 1,
        items: vec![JobItem { input: 0, presig_id: id, ssid: ssid(CHAIN, &w.key_id, 1, id, &m, PATH) }],
        prod_time: w.now,
        sealed: Sealed { enc: Bytes::default(), ct: Bytes::default() },
    };
    let seq = job.job_seq;
    w.prod.adversary_send_job(job, &[frag]);
    w.pump().await;
    assert_eq!(signed(&w), vec![rid], "request_id {rid:?} signed twice");
    // refused by the recovery cut-off itself (the 24 h pre-charge is a second, independent layer)
    let st = w.status_of(seq).unwrap();
    assert!(st.reason.contains("before the restore recovery"), "{}", st.reason);
}

fn cold_daily(w: &mut World, per_tx: u128, max_per_day: u128) {
    let mut r = policy_rules(&per_tx.to_string());
    r.max_per_day = max_per_day.to_string();
    let v = w.cold.policy_version(&w.key_id) + 1;
    w.cold.apply_quorum(&w.q.sign_policy(&PolicyBundle { target: Role::Cold, key_id: w.key_id, version: v, rules: r }), w.now).unwrap();
}

/// R-B: the COLD 24 h ledger is rolled back by a detected restore; after the runbook Unfreeze
/// COLD signs a second full daily limit within the same 24 h (honest PROD, honest UPSTREAM).
#[tokio::test(flavor = "multi_thread")]
async fn restore_then_unfreeze_forgets_the_daily_ledger() {
    let mut w = World::setup(Options::default()).await;
    cold_daily(&mut w, 2 * ETH, 4 * ETH);
    w.refill(PATH, 2).await;
    let snap = w.cold.snapshot();
    let fee = 21_000u128 * 30_000_000_000;
    for _ in 0..2 {
        let j = w.withdraw(DEST, 2 * ETH - fee, PATH).await.unwrap();
        assert_eq!(w.status_of(j).unwrap().outcome, Outcome::Signed);
    }
    let j = w.withdraw(DEST, ETH, PATH).await.unwrap();
    assert_eq!(w.status_of(j).unwrap().outcome, Outcome::Rejected, "limit reached");
    w.cold.restore_storage(&snap);
    w.cold.boot();
    w.prod.link_lost();
    w.connect_prod();
    w.pump().await;
    w.unfreeze();
    w.advance(600);
    w.refill(PATH, 1).await;
    let mut extra = 0;
    for _ in 0..2 {
        let j = w.withdraw(DEST, 2 * ETH - fee, PATH).await.unwrap();
        if w.status_of(j).unwrap().outcome == Outcome::Signed {
            extra += 1;
        }
    }
    assert_eq!(extra, 0, "COLD signed {extra} more max-size withdrawals inside the same 24 h (8 ETH > 4 ETH limit)");
}

/// R-C: a compromised PROD dates its job `max_time_skew` (120 s) ahead; COLD's ledger window is
/// evaluated at that time, so a full daily limit is signed again 86 281 s after the first.
#[tokio::test(flavor = "multi_thread")]
async fn prod_time_skew_shortens_the_rolling_window() {
    let mut w = World::setup(Options::default()).await;
    cold_daily(&mut w, 4 * ETH, 4 * ETH);
    w.refill(PATH, 1).await;
    let fee = 21_000u128 * 30_000_000_000;
    let j = w.withdraw(DEST, 4 * ETH - fee, PATH).await.unwrap();
    assert_eq!(w.status_of(j).unwrap().outcome, Outcome::Signed);
    w.advance(86_281);
    let raw = w.tx(DEST, 4 * ETH - fee);
    let (_, env) = w.envelope(raw.clone(), PATH);
    let pool = w.pool(PATH);
    let id = w.prod.held_ids(&pool)[0];
    let half = w.prod.adversary_take_half(&pool, id).unwrap();
    let y = w.prod.keyring.get(&w.key_id, 1).unwrap().group_key();
    let m = chp_chain::decode(CHAIN, &raw).unwrap().messages[0];
    let frag = prod_fragment(half, &m, &t_path(&w.key_id.0, &y, PATH)).unwrap();
    let job = Job {
        job_seq: w.prod.adversary_bump_job_seq(),
        envelope: Bytes(env),
        key_version: 1,
        items: vec![JobItem { input: 0, presig_id: id, ssid: ssid(CHAIN, &w.key_id, 1, id, &m, PATH) }],
        prod_time: w.now + 119,
        sealed: Sealed { enc: Bytes::default(), ct: Bytes::default() },
    };
    w.prod.adversary_send_job(job, &[frag]);
    w.pump().await;
    assert_eq!(signed(&w).len(), 1, "8 ETH signed within 86 281 s with a 4 ETH / 24 h limit");
}

/// R-D: batch activation did not advance COLD's state counter, so a storage image taken between
/// PresignStored and TransferAck restored *undetected* and the reboot aborted a batch that was
/// Active at PROD (Active -> Aborted, rule 2). Fixed: activation advances the counter, so the
/// restore is detected and COLD fails closed (Rollback freeze, pools discarded at both ends);
/// after the quorum's recovery Unfreeze and a fresh window, signing resumes.
#[tokio::test(flavor = "multi_thread")]
async fn restore_around_activation_is_detected() {
    let mut w = World::setup(Options::default()).await;
    let ids = w.presign_window(PATH, 1).await; // HOT exported, media not yet carried
    let b = ids[0];
    let snap = w.cold.snapshot();
    w.carry_media().await;
    assert_eq!(w.cold.batch(&b).unwrap().st, chp_engine_cold::BatchSt::Active);
    w.cold.restore_storage(&snap);
    w.cold.boot();
    w.prod.link_lost();
    w.connect_prod();
    w.pump().await;
    assert_eq!(w.cold.st.keyring.get(&w.key_id, 1).unwrap().frozen, Some(chp_wire::Fault::Rollback), "restore detected");
    assert_eq!(w.prod.available(&w.pool(PATH)), 0, "PROD dropped the batch too");
    w.advance(10);
    w.unfreeze();
    w.refill(PATH, 1).await;
    w.advance(1);
    // the restored ledger can't be trusted: the daily limit counts as used for 24 h after recovery
    let j = w.withdraw(DEST, 1, PATH).await.unwrap();
    let st = w.status_of(j).unwrap();
    assert_eq!(st.outcome, Outcome::Rejected);
    assert!(st.reason.contains("rolling 24 h"), "{}", st.reason);
    // after the window (+ skew margin), signing resumes
    w.advance(86_400 + 200);
    let j = w.withdraw(DEST, 1, PATH).await.unwrap();
    let st = w.status_of(j).unwrap();
    assert_eq!(st.outcome, Outcome::Signed, "{:?}: {}", st.outcome, st.reason);
}

/// R-D(b): an image taken before the window restored undetected; PROD's first honest withdrawal
/// was then a FAULT_PRESIG_STATE ("never issued"), blamed on PROD. Fixed: issuing ids advances
/// the state counter (restore detected, fail closed), and an id from a block the hardware
/// allocation counter handed out is a plain refusal, never a PROD fault.
#[tokio::test(flavor = "multi_thread")]
async fn restore_before_a_window_is_detected_and_not_blamed_on_prod() {
    let mut w = World::setup(Options::default()).await;
    let snap = w.cold.snapshot();
    w.refill(PATH, 1).await;
    w.cold.restore_storage(&snap);
    w.cold.boot();
    w.prod.link_lost();
    w.connect_prod();
    w.pump().await;
    assert_eq!(w.cold.st.keyring.get(&w.key_id, 1).unwrap().frozen, Some(chp_wire::Fault::Rollback), "restore detected");
    assert!(!w.cold.events.iter().any(|e| matches!(e, Event::Frozen { fault: chp_wire::Fault::PresigState, .. })), "never blamed on PROD");
}
