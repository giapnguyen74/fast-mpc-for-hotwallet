//! Regression tests for the deep security review (round 3): presign selective-failure probes.
//!
//! A malicious presign peer can turn each failing presign instance into a probe on the other
//! side's base-OT secret (DKLs23 / SoftSpoken selective failure; ~500 probes recover it). CHP
//! must therefore freeze on the FIRST failed instance, never let an abort path skip the freeze,
//! cap batch size, and never presign again with a key version that had a presign fault.

use chp_core::Event;
use chp_sim::*;
use chp_wire::{msgs::*, Fault, MsgType};

async fn malicious_hot_window(w: &mut World, batches: u32) {
    // HOT now presigns with a share of another key: COLD's instances fail their checks.
    let other = chp_mpc::dkls::local_dkg(rand::random()).await.unwrap().into_iter().next().unwrap();
    w.hot.adversary_set_share(w.key_id, 1, other);
    w.hot_boot();
    let c = w.hot.wake_counter();
    w.connect_hot();
    let d = w.cold.open_wake(w.key_id, 1, ReturnStage::PresignSync, batches, w.now + 600, c);
    w.pump().await;
    w.hot.operator_confirm_wake(d).unwrap();
    w.pump().await;
    w.cold.operator_confirm_wake().unwrap();
    w.pump().await;
}

fn cold_entry(w: &World) -> (Option<Fault>, bool) {
    let e = w.cold.st.keyring.get(&w.key_id, 1).unwrap();
    (e.frozen, e.presign_tainted)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_presign_instance_freezes_and_taints_the_key_version() {
    let mut w = World::setup(Options { batch_size: 8, ..Default::default() }).await;
    malicious_hot_window(&mut w, 2).await;
    w.cold.start_batch(PATH, w.now).unwrap();
    w.pump().await;
    // frozen with Fault::Presign, tainted, window closed, nothing stored
    assert_eq!(cold_entry(&w), (Some(Fault::Presign), true));
    assert!(!w.cold.wake_open());
    assert!(w.cold.pool(&w.pool(PATH)).unwrap().halves.is_empty());
    assert!(w.cold.events.iter().any(|e| matches!(e, Event::Info(s) if s.contains("presign-tainted"))));
    // the batch was stopped at the first failure: no instance completed its output to HOT
    assert!(w.media.is_empty());
    // Unfreeze does not clear the taint: this key version never presigns again
    w.unfreeze();
    assert_eq!(cold_entry(&w), (None, true));
    assert!(!w.cold.st.keyring.get(&w.key_id, 1).unwrap().presign_allowed());
    // HOT tainted its side too (its instances failed as well)
    assert!(w.hot.keyring.get(&w.key_id, 1).unwrap().presign_tainted);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_link_loss_after_a_failed_instance_still_freezes() {
    let mut w = World::setup(Options { batch_size: 8, ..Default::default() }).await;
    malicious_hot_window(&mut w, 1).await;
    w.cold.start_batch(PATH, w.now).unwrap();
    // Drive the rounds the way a malicious HOT would: it keeps sending presign messages and
    // never announces anything; COLD's own failure handling (poll) is not run yet either.
    for _ in 0..10_000 {
        if w.cold.sim_presign_failed() {
            break;
        }
        w.cold.sim_drain_presign_only();
        for o in std::mem::take(&mut w.cold.out) {
            if let chp_core::Out::Send { bytes, .. } = o {
                w.hot.on_frame(&bytes, w.now);
            }
        }
        w.hot.sim_drain_presign_only();
        for o in std::mem::take(&mut w.hot.out) {
            if let chp_core::Out::Send { bytes, .. } = o {
                w.cold.on_frame(chp_wire::Role::Hot, &bytes, w.now);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    assert!(w.cold.sim_presign_failed(), "the malicious rounds produced a failure at COLD");
    assert_eq!(cold_entry(&w), (None, false), "not yet handled");
    // the attacker drops the link before COLD's poll runs: the abort path must catch it
    w.cold.link_lost(chp_wire::Role::Hot);
    assert_eq!(cold_entry(&w), (Some(Fault::Presign), true), "a probe must never be free");
}

#[test]
fn batch_size_is_capped() {
    const { assert!(chp_mpc::presign::MAX_BATCH <= 16) };
}

#[allow(dead_code)]
fn _types(_: MsgType) {}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_key_version_cannot_swap_the_group_key() {
    let w = World::setup(Options::default()).await;
    let mut cold = w;
    let m: KeyManifest = cold.cold.st.trust.verify_quorum(&cold.manifest, MsgType::KeyManifest).unwrap();
    // a quorum-signed "refresh" manifest v2 with another group key is refused everywhere
    let mut evil = m.clone();
    evil.key_version = 2;
    evil.group_key = chp_wire::Bytes(chp_crypto::ecdsa::enc_point(&(k256::ProjectivePoint::GENERATOR * k256::Scalar::from(7u64))).to_vec());
    let signed = cold.q.sign(MsgType::KeyManifest, &evil);
    assert!(cold.cold.apply_quorum(&signed, cold.now).is_err());
    assert!(cold.prod.apply_quorum(&signed, cold.now).is_err());
    // a different manifest for the installed version 1 is refused too
    let mut again = m.clone();
    again.chain = "evm:1".into();
    assert!(cold.prod.apply_quorum(&cold.q.sign(MsgType::KeyManifest, &again), cold.now).is_err());
    // a genuine v2 (same Y) is accepted
    let mut ok = m;
    ok.key_version = 2;
    assert!(cold.cold.apply_quorum(&cold.q.sign(MsgType::KeyManifest, &ok), cold.now).is_ok());
    let _ = &mut cold;
}

#[tokio::test(flavor = "multi_thread")]
async fn junk_jobs_cannot_grow_colds_sealed_state() {
    let mut w = World::setup(Options::default()).await;
    let base = w.prod.next_job_seq();
    for i in 0..5_000u64 {
        let job = Job {
            job_seq: base + i,
            envelope: chp_wire::Bytes::default(),
            key_version: 1,
            items: vec![],
            prod_time: w.now,
            sealed: Sealed { enc: chp_wire::Bytes::default(), ct: chp_wire::Bytes::default() },
        };
        w.prod.adversary_send_job_raw(job);
        if i % 500 == 0 {
            w.pump().await;
        }
    }
    w.pump().await;
    assert!(w.cold.st.jobs.len() <= 4097, "job table bounded, got {}", w.cold.st.jobs.len());
}
