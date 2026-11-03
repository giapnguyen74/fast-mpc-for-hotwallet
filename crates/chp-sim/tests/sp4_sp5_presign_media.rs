//! SP4 wake windows + presign, SP5 media transfer and activation.

use chp_core::Event;
use chp_engine_cold::BatchSt;
use chp_engine_hot::Mode;
use chp_engine_prod::PBatch;
use chp_sim::*;
use chp_wire::{decode_canonical, msgs::*, Bytes, Role};

fn refused(events: &[Event], needle: &str) -> bool {
    events.iter().any(|e| matches!(e, Event::Refused { why, .. } if why.contains(needle)))
}

#[tokio::test(flavor = "multi_thread")]
async fn wake_window_needs_exact_counter_and_both_operators() {
    let mut w = World::setup(Options::default()).await;
    // stale counter (a replayed / precomputed WakeOpen)
    w.hot.boot();
    let c = w.hot.wake_counter();
    w.connect_hot();
    w.cold.open_wake(w.key_id, 1, ReturnStage::PresignSync, 1, w.now + 600, c + 5);
    w.pump().await;
    assert!(refused(&w.hot.events, "wake_seq"), "{:?}", w.hot.events);
    assert!(!w.hot.is_open());

    // digest mismatch at HOT's operator: the window never opens (and the counter was spent)
    w.hot.boot();
    let c = w.hot.wake_counter();
    w.connect_hot();
    w.cold.open_wake(w.key_id, 1, ReturnStage::PresignSync, 1, w.now + 600, c);
    w.pump().await;
    assert_eq!(w.hot.wake_counter(), c + 1, "counter advanced before accepting");
    assert!(w.hot.operator_confirm_wake(chp_wire::B32([0; 32])).is_err());
    assert!(!w.hot.is_open());

    // the same wake_seq cannot be used again
    w.hot.boot();
    w.connect_hot();
    w.cold.open_wake(w.key_id, 1, ReturnStage::PresignSync, 1, w.now + 600, c);
    w.pump().await;
    assert!(refused(&w.hot.events, "wake_seq"));

    // COLD will not open the window without HOT's WakeAccept
    assert!(w.cold.operator_confirm_wake().is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn high_security_mode_refuses_presign_sync() {
    let mut w = World::setup(Options { mode: Mode::HighSecurity, ..Default::default() }).await;
    w.hot.boot();
    let c = w.hot.wake_counter();
    w.connect_hot();
    w.cold.open_wake(w.key_id, 1, ReturnStage::PresignSync, 1, w.now + 600, c);
    w.pump().await;
    assert!(refused(&w.hot.events, "does not allow"), "{:?}", w.hot.events);
}

#[tokio::test(flavor = "multi_thread")]
async fn presign_only_for_paths_in_the_book() {
    let mut w = World::setup(Options { paths: vec![PATH], ..Default::default() }).await;
    // COLD refuses to open a batch for a path outside its book
    w.hot.boot();
    let c = w.hot.wake_counter();
    w.connect_hot();
    let d = w.cold.open_wake(w.key_id, 1, ReturnStage::PresignSync, 2, w.now + 600, c);
    w.pump().await;
    w.hot.operator_confirm_wake(d).unwrap();
    w.pump().await;
    w.cold.operator_confirm_wake().unwrap();
    w.pump().await;
    assert!(w.cold.start_batch("m/not-in-book", w.now).is_err());
    let b = w.cold.start_batch(PATH, w.now).unwrap();
    w.pump().await;
    assert_eq!(w.cold.batch(&b).unwrap().st, BatchSt::Exported);
    assert_eq!(w.media.len(), 1, "HOT wrote one bundle");
}

#[tokio::test(flavor = "multi_thread")]
async fn batch_activates_only_with_three_matching_digests() {
    let mut w = World::setup(Options::default()).await;
    let ids = w.presign_window(PATH, 1).await;
    let b = ids[0];
    // Before PROD imports: COLD has its digest and HOT's, but not PROD's.
    assert_eq!(w.cold.batch(&b).unwrap().st, BatchSt::Exported);
    assert!(w.cold.batch(&b).unwrap().own.is_some() && w.cold.batch(&b).unwrap().own == w.cold.batch(&b).unwrap().hot);
    assert!(w.withdraw(DEST, 1, PATH).await.is_err(), "nothing usable before activation");
    w.carry_media().await;
    assert_eq!(w.cold.batch(&b).unwrap().st, BatchSt::Active);
    assert_eq!(w.prod.batch_state(&b), Some(PBatch::Active));
}

#[tokio::test(flavor = "multi_thread")]
async fn tampered_or_foreign_bundles_change_nothing_and_replays_are_ignored() {
    let mut w = World::setup(Options::default()).await;
    let ids = w.presign_window(PATH, 1).await;
    let bundle = w.media[0].clone();
    // flip a byte in the signed transfer
    let mut mb: MediaBundle = decode_canonical(&bundle).unwrap();
    let mut t = mb.transfer.0.clone();
    let n = t.len();
    t[n - 70] ^= 1;
    mb.transfer = Bytes(t);
    assert!(w.prod.import_media(&chp_wire::encode(&mb), w.now).is_err());
    assert_eq!(w.prod.batch_state(&ids[0]), None, "a bundle failing authentication changes nothing");
    // a bundle wrapped with PROD's own certificate instead of HOT's
    let mut mb2: MediaBundle = decode_canonical(&bundle).unwrap();
    mb2.hot_cert = Bytes(w.prod.cert().to_vec());
    assert!(w.prod.import_media(&chp_wire::encode(&mb2), w.now).is_err());
    assert_eq!(w.prod.batch_state(&ids[0]), None);
    // the genuine bundle still imports and activates
    w.carry_media().await;
    assert_eq!(w.prod.batch_state(&ids[0]), Some(PBatch::Active));
    // replaying it is ignored
    assert!(w.prod.import_media(&bundle, w.now).is_ok());
    assert_eq!(w.prod.available(&w.pool(PATH)), 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn late_media_is_aborted_and_cannot_revive() {
    let mut w = World::setup(Options::default()).await;
    let ids = w.presign_window(PATH, 1).await;
    // the courier is late: COLD aborts at import_deadline and tells PROD
    w.advance(3601);
    w.pump().await;
    assert_eq!(w.cold.batch(&ids[0]).unwrap().st, BatchSt::Aborted);
    assert_eq!(w.prod.batch_state(&ids[0]), Some(PBatch::Aborted));
    let pool = w.cold.pool(&w.pool(PATH)).unwrap();
    assert!(pool.halves.is_empty(), "COLD deleted its pending halves");
    // the late bundle is refused
    let b = w.media.pop().unwrap();
    assert!(w.prod.import_media(&b, w.now).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn digest_mismatch_aborts_and_link_loss_aborts_pending() {
    let mut w = World::setup(Options::default()).await;
    let ids = w.presign_window(PATH, 2).await;
    // COLD's own digest differs from the others (e.g. a substituted bundle): abort.
    w.cold.st.batches.get_mut(&ids[0]).unwrap().own = Some(chp_wire::B32([9; 32]));
    let b0 = w.media.remove(0);
    w.prod.import_media(&b0, w.now).unwrap();
    w.pump().await;
    assert_eq!(w.cold.batch(&ids[0]).unwrap().st, BatchSt::Aborted);
    assert_eq!(w.prod.batch_state(&ids[0]), Some(PBatch::Aborted));
    // Second batch: PROD imports while its COLD link is down, then notices the loss.
    w.prod.link_lost();
    let b1 = w.media.remove(0);
    w.prod.import_media(&b1, w.now).unwrap();
    assert_eq!(w.prod.batch_state(&ids[1]), Some(PBatch::Pending));
    w.prod.link_lost();
    assert_eq!(w.prod.batch_state(&ids[1]), Some(PBatch::Aborted));
    assert_eq!(w.prod.available(&w.pool(PATH)), 0);
    let _ = Role::Prod;
}

#[tokio::test(flavor = "multi_thread")]
async fn hot_holds_nothing_after_export() {
    let mut w = World::setup(Options::default()).await;
    w.presign_window(PATH, 1).await;
    // HOT is powered off; it never kept halves (erase on export). The only copy of HOT's
    // halves is the ciphertext bundle, readable only by PROD's enclave.
    let mb: MediaBundle = decode_canonical(&w.media[0]).unwrap();
    let sm: chp_wire::SignedMsg = decode_canonical(&mb.transfer.0).unwrap();
    let tr: PresigTransfer = decode_canonical(&sm.body.0).unwrap();
    let sealed = chp_crypto::seal::Sealed { enc: tr.sealed.enc.0.clone(), ct: tr.sealed.ct.0.clone() };
    assert!(w.cold.enclave.wrap.open(&sealed, b"chp-transfer-v1", &[]).is_err(), "COLD cannot read PROD's bundle");
    assert!(!w.hot.busy() && !w.hot.is_open());
}
