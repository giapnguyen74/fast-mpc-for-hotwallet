//! Regression tests for security review round 2 (docs/SECURITY.md, R1–R…).

use chp_core::{digest::ssid, Event, Out};
use chp_crypto::{derive::t_path, ecdsa::prod_fragment};
use chp_engine_hot::Mode;
use chp_sim::*;
use chp_wire::{msgs::*, Bytes, Fault, MsgType, Role, B32};

const ETH: u128 = 1_000_000_000_000_000_000;

fn frozen(w: &World) -> Option<Fault> {
    w.cold.st.keyring.get(&w.key_id, 1).unwrap().frozen
}

fn cold_daily(w: &mut World, max_per_day: u128) {
    let mut r = policy_rules("10000000000000000000");
    r.max_per_day = max_per_day.to_string();
    let v = w.cold.policy_version(&w.key_id) + 1;
    w.cold.apply_quorum(&w.q.sign_policy(&PolicyBundle { target: Role::Cold, key_id: w.key_id, version: v, rules: r }), w.now).unwrap();
}

fn prod_daily(w: &mut World, max_per_day: u128) {
    let mut r = policy_rules("10000000000000000000");
    r.max_per_day = max_per_day.to_string();
    let v = w.prod.policy_version(&w.key_id) + 1;
    w.prod.apply_quorum(&w.q.sign_policy(&PolicyBundle { target: Role::Prod, key_id: w.key_id, version: v, rules: r }), w.now).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn r1_restoring_a_prefrozen_snapshot_cannot_be_undone_by_an_old_unfreeze() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 1).await;
    // incident 1: frozen with E1, snapshot taken while frozen
    w.cold.freeze(w.key_id, 1, Fault::FinalVerify, B32([1; 32]), None);
    let snap = w.cold.snapshot();
    let u1 = w.unfreeze(); // public Unfreeze naming E1
    // then the quorum revokes a compromised UPSTREAM
    let up = B32(chp_crypto::ident::key_hash(&w.upstream.public()));
    let rl = w.q.sign(MsgType::RevocationList, &RevocationList { version: 1, revoked: vec![Revoked::party(Role::Upstream, up)] });
    w.cold.apply_quorum(&rl, w.now).unwrap();
    // attacker restores the pre-revocation (frozen-with-E1) storage, reboots, replays u1
    w.cold.restore_storage(&snap);
    w.cold.boot();
    assert_eq!(frozen(&w), Some(Fault::Rollback), "Rollback overwrites the old freeze");
    assert!(w.cold.apply_quorum(&u1, w.now).is_err(), "an Unfreeze minted before the restore cannot lift it");
    assert_eq!(frozen(&w), Some(Fault::Rollback));
    // the restore is announced to PROD with the evidence
    assert!(w.cold.events.iter().any(|e| matches!(e, Event::Info(s) if s.contains("STORAGE RESTORE DETECTED"))));
    w.prod.link_lost();
    w.connect_prod();
    w.pump().await;
    assert_eq!(w.prod.keyring.get(&w.key_id, 1).unwrap().frozen, Some(Fault::Rollback), "PROD froze on the notice");
}

#[tokio::test(flavor = "multi_thread")]
async fn r2_future_dated_envelopes_are_refused_by_cold() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 1).await;
    let raw = w.tx(DEST, 1);
    let (_, env) = w.envelope(raw.clone(), PATH);
    // re-sign the envelope as UPSTREAM, dated 1000 s ahead
    let f: chp_wire::SignedMsg = chp_wire::decode_canonical(&env).unwrap();
    let mut e: WithdrawalEnvelope = chp_wire::decode_canonical(&f.body.0).unwrap();
    e.upstream_time = w.now + 1000;
    e.not_after = w.now + 1100;
    let env = chp_auth::sign_body(&w.upstream, MsgType::WithdrawalEnvelope, 0, &e);
    assert!(w.prod.withdraw(&env, w.now).is_err(), "PROD refuses it");
    // a compromised PROD forwards it with a matching prod_time: COLD refuses it too
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
        prod_time: w.now + 1000,
        sealed: Sealed { enc: Bytes::default(), ct: Bytes::default() },
    };
    let seq = job.job_seq;
    w.prod.adversary_send_job(job, &[frag]);
    w.pump().await;
    let st = w.status_of(seq).unwrap();
    assert_eq!(st.outcome, Outcome::Rejected);
    assert!(st.reason.contains("future"), "{}", st.reason);
}

#[tokio::test(flavor = "multi_thread")]
async fn r3_a_crash_between_sealing_and_the_counter_is_not_a_restore() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 1).await;
    // emulate: sealed state written with hw+1, crash before the hardware increment
    w.cold.st.state_counter = w.cold.enclave.counters.read("state") + 1;
    w.cold.boot();
    assert_eq!(frozen(&w), None, "an honest crash does not freeze the key");
}

#[tokio::test(flavor = "multi_thread")]
async fn r4_revoking_a_requester_or_custodian_discards_no_pool() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 1).await;
    let req = B32(chp_crypto::ident::key_hash(&w.requester.public()));
    let cust = B32(chp_crypto::ident::key_hash(&w.q.ceremony.0[4].public()));
    let rl = w.q.sign(MsgType::RevocationList, &RevocationList { version: 1, revoked: vec![Revoked::party(Role::Requester, req), Revoked::custodian(cust)] });
    w.cold.apply_quorum(&rl, w.now).unwrap();
    w.prod.apply_quorum(&rl, w.now).unwrap();
    assert_eq!(w.cold.pool(&w.pool(PATH)).unwrap().active_ids().len(), 4);
    assert_eq!(w.prod.available(&w.pool(PATH)), 4);
}

/// Deliver PROD→COLD frames with a host-supplied COLD clock; COLD→PROD at the real clock.
fn shuttle(w: &mut World, cold_clock: u64) -> usize {
    let mut n = 0;
    for _ in 0..10 {
        for o in std::mem::take(&mut w.prod.out) {
            match o {
                Out::Send { to: Role::Cold, bytes } => w.cold.on_frame(Role::Prod, &bytes, cold_clock),
                Out::Broadcast { .. } => n += 1,
                _ => {}
            }
        }
        for o in std::mem::take(&mut w.cold.out) {
            if let Out::Send { to: Role::Prod, bytes } = o {
                w.prod.on_frame(&bytes, w.now)
            }
        }
    }
    n
}

async fn backdated_run(honest: bool) -> usize {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 2).await;
    cold_daily(&mut w, 3 * ETH / 2); // COLD: 1.5 ETH per rolling 24 h
    w.advance(30 * 86_400);
    let mut signed = 0;
    for i in 0..5u64 {
        let raw = w.tx(DEST, ETH);
        let (_, env) = w.envelope(raw, PATH);
        w.prod.withdraw(&env, w.now).expect("PROD admits");
        // the malicious host walks COLD's clock forward through the past, 2 days per job, so
        // each job would see an empty 24 h window
        let clock = if honest { w.now } else { w.now - (20 - 2 * i) * 86_400 };
        signed += shuttle(&mut w, clock);
        w.advance(5);
    }
    signed
}

#[tokio::test(flavor = "multi_thread")]
async fn r5_a_backdated_cold_host_clock_cannot_reset_the_daily_limit() {
    assert_eq!(backdated_run(true).await, 1, "control: real clock, 1.5 ETH/day → one 1 ETH withdrawal");
    assert!(backdated_run(false).await <= 1, "a host walking COLD's clock through the past gains nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn r6_a_burst_cannot_bypass_prods_daily_limit() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 2).await;
    prod_daily(&mut w, 3 * ETH / 2);
    let mut admitted = 0;
    for _ in 0..3 {
        let raw = w.tx(DEST, ETH);
        let (_, env) = w.envelope(raw, PATH);
        if w.prod.withdraw(&env, w.now).is_ok() {
            admitted += 1; // no Status has come back yet
        }
    }
    assert_eq!(admitted, 1, "the reservation counts the pending job");
}

#[tokio::test(flavor = "multi_thread")]
async fn r7_a_dkg_window_cannot_refill_the_old_key() {
    let mut w = World::setup(Options { mode: Mode::HighSecurity, ..Default::default() }).await;
    w.hot_boot();
    let c = w.hot.wake_counter();
    w.connect_hot();
    w.cold.open_wake(w.key_id, 1, ReturnStage::Dkg, 1, w.now + 600, c);
    w.pump().await;
    assert!(w.hot.events.iter().any(|e| matches!(e, Event::Refused { why, .. } if why.contains("new key"))), "{:?}", w.hot.events);
}

#[tokio::test(flavor = "multi_thread")]
async fn r8_a_compromised_hot_cannot_abort_an_active_batch() {
    let mut w = World::setup(Options::default()).await;
    let ids = w.refill(PATH, 1).await;
    // HOT is woken again; it sends a PresignRefuse naming the already active batch
    w.hot_boot();
    let c = w.hot.wake_counter();
    w.connect_hot();
    let d = w.cold.open_wake(w.key_id, 1, ReturnStage::PresignSync, 1, w.now + 600, c);
    w.pump().await;
    w.hot.operator_confirm_wake(d).unwrap();
    w.pump().await;
    w.hot.adversary_send(MsgType::PresignRefuse, &PresignRefuse { batch_id: ids[0], reason: RefuseReason::BadBatch });
    w.hot.adversary_send(MsgType::PresignStored, &PresignStored { batch_id: ids[0], digest: B32([0; 32]) });
    w.pump().await;
    assert_eq!(w.cold.batch(&ids[0]).unwrap().st, chp_engine_cold::BatchSt::Active);
    assert_eq!(w.cold.pool(&w.pool(PATH)).unwrap().active_ids().len(), 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn r9_a_far_future_host_clock_does_not_disable_cold() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 1).await;
    w.cold.poll(w.now + 10 * 365 * 86_400).await; // one bogus tick
    let j = w.withdraw(DEST, 1, PATH).await.unwrap();
    assert_eq!(w.status_of(j).unwrap().outcome, Outcome::Signed);
}

#[tokio::test(flavor = "multi_thread")]
async fn r10_a_pending_manifest_does_not_stop_the_current_version() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 1).await;
    let mut m: KeyManifest = w.cold.st.trust.verify_quorum(&w.manifest, MsgType::KeyManifest).unwrap();
    m.key_version = 2;
    let m2 = w.q.sign(MsgType::KeyManifest, &m);
    w.cold.apply_quorum(&m2, w.now).unwrap();
    w.prod.apply_quorum(&m2, w.now).unwrap();
    let j = w.withdraw(DEST, 1, PATH).await.unwrap();
    assert_eq!(w.status_of(j).unwrap().outcome, Outcome::Signed, "v1 keeps signing until v2 is activated");
}
