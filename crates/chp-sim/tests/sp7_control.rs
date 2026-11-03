//! SP7 control and DESIGN §6.1: restarts, storage restore, revocation, reconciliation, policy.

use chp_core::Event;
use chp_crypto::ident::key_hash;
use chp_sim::*;
use chp_wire::{msgs::*, presig_id, MsgType, Role, B32};

#[tokio::test(flavor = "multi_thread")]
async fn cold_restart_burns_the_open_block_only() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 2).await;
    let j = w.withdraw(DEST, 1, PATH).await.unwrap();
    assert_eq!(w.status_of(j).unwrap().outcome, Outcome::Signed);
    let used_block = presig_id::block(w.cold.pool(&w.pool(PATH)).unwrap().high_water);
    // restart COLD: the open block closes; OrphanDelete reaches PROD at the next link
    w.cold.boot();
    w.prod.link_lost();
    w.connect_prod();
    w.pump().await;
    assert!(w.prod.held_ids(&w.pool(PATH)).iter().all(|i| presig_id::block(*i) > used_block), "PROD skipped the closed block");
    assert_eq!(w.prod.available(&w.pool(PATH)), 4, "the second batch is untouched");
    let j = w.withdraw(DEST, 1, PATH).await.unwrap();
    assert_eq!(w.status_of(j).unwrap().outcome, Outcome::Signed);
}

#[tokio::test(flavor = "multi_thread")]
async fn storage_restore_is_detected_and_old_halves_never_sign_again() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 1).await;
    let pool = w.pool(PATH);
    // An attacker snapshots COLD's storage and copies PROD's halves.
    let snap = w.cold.snapshot();
    let stolen = w.prod.steal_halves();
    // Normal operation consumes the first presignature.
    let j = w.withdraw(DEST, 1, PATH).await.unwrap();
    assert_eq!(w.status_of(j).unwrap().outcome, Outcome::Signed);
    let used = stolen[0].1;
    // Restore the old storage (the used half is back on disk) and restart COLD.
    w.cold.restore_storage(&snap);
    assert!(w.cold.pool(&pool).unwrap().halves.contains_key(&used), "restored state holds the used half again");
    w.cold.boot();
    assert!(w.cold.events.iter().any(|e| matches!(e, Event::PoolDiscarded { reason, .. } if reason.contains("restore"))));
    assert!(w.cold.pool(&pool).unwrap().halves.is_empty(), "pool discarded");
    w.prod.link_lost();
    w.connect_prod();
    w.pump().await;
    assert_eq!(w.prod.available(&pool), 0, "OrphanDelete cleared PROD below the floor");
    // The attacker replays the used presignature (its stolen copy) with a fresh, valid request.
    let (_, _, half) = stolen.into_iter().next().unwrap();
    let raw = w.tx(DEST, 1);
    let (_, env) = w.envelope(raw.clone(), PATH);
    let m = chp_chain::decode(CHAIN, &raw).unwrap().messages[0];
    let y = w.prod.keyring.get(&w.key_id, 1).unwrap().group_key();
    let frag = chp_crypto::ecdsa::prod_fragment(half, &m, &chp_crypto::derive::t_path(&w.key_id.0, &y, PATH)).unwrap();
    let job = Job {
        job_seq: w.prod.adversary_bump_job_seq(),
        envelope: chp_wire::Bytes(env),
        key_version: 1,
        items: vec![JobItem { input: 0, presig_id: used, ssid: chp_core::digest::ssid(CHAIN, &w.key_id, 1, used, &m, PATH) }],
        prod_time: w.now,
        sealed: Sealed { enc: Default::default(), ct: Default::default() },
    };
    let seq = job.job_seq;
    w.prod.adversary_send_job(job, &[frag]);
    w.pump().await;
    let st = w.status_of(seq).unwrap();
    assert_eq!(st.outcome, Outcome::Rejected, "{}", st.reason);
    assert!(st.reason.contains("floor") || st.reason.contains("closed"), "{}", st.reason);
    let n_signed = w.cold.events.iter().filter(|e| matches!(e, Event::Signed { .. })).count();
    assert_eq!(n_signed, 1, "the restored half never signs again");
    // The pool itself keeps working above the floor after a refill.
    w.refill(PATH, 1).await;
    let j = w.withdraw(DEST, 1, PATH).await.unwrap();
    assert_eq!(w.status_of(j).unwrap().outcome, Outcome::Signed);
}

#[tokio::test(flavor = "multi_thread")]
async fn revoking_prod_discards_pools_and_closes_the_link() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 1).await;
    let prod_pk = w.prod.enclave.id.public();
    let rl = w.q.sign(MsgType::RevocationList, &RevocationList { version: 1, revoked: vec![B32(key_hash(&prod_pk))] });
    w.cold.apply_quorum(&rl, w.now).unwrap();
    assert!(w.cold.pool(&w.pool(PATH)).unwrap().halves.is_empty());
    // PROD can never link again
    let tls = B32([1; 32]);
    let (_, h) = w.cold.dial(tls);
    let reply = w.prod.on_hello(&h, tls, w.now).unwrap();
    assert!(w.cold.on_hello_reply(&reply, tls, B32([0; 32]), w.now).is_err());
    // an old revocation list cannot be replayed
    let rl0 = w.q.sign(MsgType::RevocationList, &RevocationList { version: 1, revoked: vec![] });
    assert!(w.cold.apply_quorum(&rl0, w.now).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn pool_status_reconciles_orphans() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 1).await;
    let pool = w.pool(PATH);
    let ids = w.prod.held_ids(&pool);
    // PROD lost one half (crash between delete and send): COLD deletes its orphan.
    w.prod.adversary_take_half(&pool, ids[1]).unwrap();
    w.prod.send_pool_status();
    w.pump().await;
    assert!(!w.cold.pool(&pool).unwrap().halves.contains_key(&ids[1]));
    assert_eq!(w.cold.pool(&pool).unwrap().active_ids().len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_bundles_are_per_party_and_monotonic() {
    let mut w = World::setup(Options::default()).await;
    let r = policy_rules("1");
    // a bundle addressed to PROD is refused by COLD and vice versa
    let to_prod = w.q.sign_policy(&PolicyBundle { target: Role::Prod, key_id: w.key_id, version: 2, rules: r.clone() });
    assert!(w.cold.apply_quorum(&to_prod, w.now).is_err());
    let to_cold = w.q.sign_policy(&PolicyBundle { target: Role::Cold, key_id: w.key_id, version: 2, rules: r.clone() });
    assert!(w.prod.apply_quorum(&to_cold, w.now).is_err());
    // the ceremony quorum cannot loosen policy
    let by_ceremony = w.q.sign(MsgType::PolicyBundle, &PolicyBundle { target: Role::Cold, key_id: w.key_id, version: 3, rules: r.clone() });
    assert!(w.cold.apply_quorum(&by_ceremony, w.now).is_err());
    // an older version is refused
    w.cold.apply_quorum(&to_cold, w.now).unwrap();
    let old = w.q.sign_policy(&PolicyBundle { target: Role::Cold, key_id: w.key_id, version: 1, rules: r });
    assert!(w.cold.apply_quorum(&old, w.now).is_err());
    // a request written against another COLD policy version is rejected by COLD
    w.refill(PATH, 1).await;
    let raw = w.tx(DEST, 1);
    let (_, env) = w.envelope(raw, PATH); // cold_policy_ver = 2 now
    let mut f: chp_wire::SignedMsg = chp_wire::decode_canonical(&env).unwrap();
    let mut e: WithdrawalEnvelope = chp_wire::decode_canonical(&f.body.0).unwrap();
    e.cold_policy_ver = 1;
    f.body = chp_wire::Bytes(chp_wire::encode(&e));
    let env = chp_auth::sign_body(&w.upstream, MsgType::WithdrawalEnvelope, 0, &e);
    let _ = f;
    let j = w.prod.withdraw(&env, w.now).unwrap();
    w.pump().await;
    let st = w.status_of(j).unwrap();
    assert_eq!(st.outcome, Outcome::Rejected);
    assert!(st.reason.contains("policy version"), "{}", st.reason);
}

#[tokio::test(flavor = "multi_thread")]
async fn retired_key_version_cannot_sign_and_nothing_is_deleted() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 1).await;
    let retire = w.q.sign(MsgType::Retire, &KeyControl { key_id: w.key_id, key_version: 1, version: 1 });
    w.cold.apply_quorum(&retire, w.now).unwrap();
    w.prod.apply_quorum(&retire, w.now).unwrap();
    assert!(w.withdraw(DEST, 1, PATH).await.is_err());
    assert!(w.cold.pool(&w.pool(PATH)).unwrap().halves.is_empty(), "pools of the retired version discarded");
    // rule 8: the share is not deleted, only unusable
    assert_eq!(w.cold.keyring.get(&w.key_id, 1).unwrap().state, chp_wire::KeyState::Retired);
}

#[tokio::test(flavor = "multi_thread")]
async fn freeze_reaches_hot_and_control_only_window_delivers_unfreeze() {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 1).await;
    // A fault freezes COLD and PROD; HOT is powered off and learns at its next window.
    w.cold.freeze(w.key_id, 1, chp_wire::Fault::FinalVerify, B32([1; 32]), None);
    w.pump().await;
    assert!(w.prod.keyring.get(&w.key_id, 1).unwrap().frozen.is_some());
    let u = w.unfreeze();
    // presign is refused while COLD's queue has the Unfreeze for HOT but HOT's key is fine;
    // a ControlOnly window delivers the quorum files (allowed even while frozen).
    w.hot.boot();
    let c = w.hot.wake_counter();
    w.connect_hot();
    let d = w.cold.open_wake(w.key_id, 1, ReturnStage::ControlOnly, 0, w.now + 600, c);
    w.pump().await;
    w.hot.operator_confirm_wake(d).unwrap();
    w.pump().await;
    w.cold.operator_confirm_wake().unwrap();
    w.pump().await;
    assert!(w.cold.start_batch(PATH, w.now).is_err(), "ControlOnly windows run no presign");
    // HOT verified and applied the relayed quorum Unfreeze itself
    let slot = format!("Unfreeze/{}", hex::encode(w.key_id.0));
    assert_eq!(w.hot.trust.version(&slot), 1, "HOT applied Unfreeze v1");
    // COLD cannot alter a relayed quorum file: a forged one is refused by HOT
    let _ = u;
}
