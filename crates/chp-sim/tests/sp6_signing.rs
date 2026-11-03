//! SP6 signing: admission, COLD's independent checks, compromised-PROD behaviour, freezes.

use chp_auth::sign_body;
use chp_core::{digest::ssid, Event, Out};
use chp_crypto::{derive::t_path, ecdsa::prod_fragment, ident::IdKey};
use chp_sim::*;
use chp_wire::{
    decode_canonical, msgs::*, presig_id, Bytes, Fault, MsgType, SignedMsg, B32,
};

const ETH: u128 = 1_000_000_000_000_000_000;
const ATTACKER: &str = "0x6666666666666666666666666666666666666666";

async fn ready() -> World {
    let mut w = World::setup(Options::default()).await;
    w.refill(PATH, 2).await;
    w
}

fn signed_count(w: &World) -> usize {
    w.cold.events.iter().filter(|e| matches!(e, Event::Signed { .. })).count()
}

fn frozen(w: &World) -> bool {
    w.cold.keyring.get(&w.key_id, 1).unwrap().frozen.is_some()
}

#[tokio::test(flavor = "multi_thread")]
async fn admission_refusals_consume_no_presignature() {
    let mut w = ready().await;
    let pool = w.pool(PATH);
    let before = w.prod.available(&pool);

    // unknown signer (not UPSTREAM)
    let evil = IdKey::generate(&mut rand::thread_rng());
    let raw = w.tx(DEST, 1);
    let (_, env) = w.envelope(raw.clone(), PATH);
    let mut f: SignedMsg = decode_canonical(&env).unwrap();
    let body: WithdrawalEnvelope = decode_canonical(&f.body.0).unwrap();
    let forged = sign_body(&evil, MsgType::WithdrawalEnvelope, 0, &body);
    assert!(w.prod.withdraw(&forged, w.now).is_err());
    // tampered envelope (signature no longer matches)
    let mut b2 = body.clone();
    b2.raw_tx = Bytes(w.tx(ATTACKER, 1));
    f.body = Bytes(chp_wire::encode(&b2));
    assert!(w.prod.withdraw(&chp_wire::encode(&f), w.now).is_err());
    // destination not on PROD's allowlist
    let raw = w.tx(ATTACKER, 1);
    let (_, env) = w.envelope(raw, PATH);
    assert!(w.prod.withdraw(&env, w.now).is_err());
    // over PROD's per-tx limit
    let raw = w.tx(DEST, 11 * ETH);
    let (_, env) = w.envelope(raw, PATH);
    assert!(w.prod.withdraw(&env, w.now).is_err());
    // path not in the address book
    let raw = w.tx(DEST, 1);
    let (_, env) = w.envelope(raw, "m/not-in-book");
    assert!(w.prod.withdraw(&env, w.now).is_err());
    // expired
    let raw = w.tx(DEST, 1);
    let (_, env) = w.envelope(raw, PATH);
    assert!(w.prod.withdraw(&env, w.now + 1000).is_err());
    // replayed request_id
    let raw = w.tx(DEST, 1);
    let (_, env) = w.envelope(raw, PATH);
    assert!(w.prod.withdraw(&env, w.now).is_ok());
    w.pump().await;
    let after_one = w.prod.available(&pool);
    assert!(w.prod.withdraw(&env, w.now).is_err(), "replay refused");
    assert_eq!(after_one, before - 1, "only the admitted request used a presignature");
    assert_eq!(w.prod.available(&pool), after_one);
}

#[tokio::test(flavor = "multi_thread")]
async fn cold_policy_is_independent_and_rejects_alone() {
    // PROD allows 10 ETH per tx, COLD only 1 ETH: COLD refuses on its own.
    let mut w = World::setup(Options { cold_max_per_tx: ETH.to_string(), ..Default::default() }).await;
    w.refill(PATH, 1).await;
    let pool = w.pool(PATH);
    let (p0, c0) = (w.prod.available(&pool), w.cold.pool(&pool).unwrap().active_ids().len());
    let job = w.withdraw(DEST, 5 * ETH, PATH).await.expect("PROD admits");
    let st = w.status_of(job).unwrap();
    assert_eq!(st.outcome, Outcome::Rejected);
    assert!(st.reason.contains("COLD policy"), "{}", st.reason);
    assert!(w.broadcasts.is_empty());
    assert!(!frozen(&w), "a policy reject is not a fault");
    // REJECTED burns the presignature on both sides.
    assert_eq!(w.prod.available(&pool), p0 - 1);
    assert_eq!(w.cold.pool(&pool).unwrap().active_ids().len(), c0 - 1);
}

/// Build a job the way a compromised PROD would, with full control of its fragments.
fn craft(w: &mut World, env: &[u8], raw_for_frag: &[u8], id: u64, ssid_raw: &[u8]) -> (Job, Vec<chp_crypto::ecdsa::EcdsaFragment>) {
    let pool = w.pool(PATH);
    let half = w.prod.adversary_take_half(&pool, id).expect("half held");
    let y = w.prod.keyring.get(&w.key_id, 1).unwrap().group_key();
    let t = t_path(&w.key_id.0, &y, PATH);
    let m_frag = chp_chain::decode(CHAIN, raw_for_frag).unwrap().messages[0];
    let m_ssid = chp_chain::decode(CHAIN, ssid_raw).unwrap().messages[0];
    let frag = prod_fragment(half, &m_frag, &t).unwrap();
    let job = Job {
        job_seq: w.prod.adversary_bump_job_seq(),
        envelope: Bytes(env.to_vec()),
        key_version: 1,
        items: vec![JobItem { input: 0, presig_id: id, ssid: ssid(CHAIN, &w.key_id, 1, id, &m_ssid, PATH) }],
        prod_time: w.now,
        sealed: Sealed { enc: Bytes::default(), ct: Bytes::default() },
    };
    (job, vec![frag])
}

fn first_id(w: &World) -> u64 {
    w.prod.held_ids(&w.pool(PATH))[0]
}

#[tokio::test(flavor = "multi_thread")]
async fn compromised_prod_cannot_redirect_funds() {
    let mut w = ready().await;
    // UPSTREAM asks for DEST; PROD computes its fragment for ATTACKER's transaction.
    let good = w.tx(DEST, ETH);
    let evil = w.tx(ATTACKER, 9 * ETH);
    let (_, env) = w.envelope(good.clone(), PATH);
    let id = first_id(&w);
    let (job, frags) = craft(&mut w, &env, &evil, id, &good);
    let seq = job.job_seq;
    w.prod.adversary_send_job(job, &frags);
    w.pump().await;
    let st = w.status_of(seq).unwrap();
    assert_eq!(st.outcome, Outcome::Fault(Fault::FinalVerify), "{}", st.reason);
    assert!(w.broadcasts.is_empty(), "nothing invalid is broadcast");
    assert!(frozen(&w), "COLD froze the key");
    assert!(w.prod.keyring.get(&w.key_id, 1).unwrap().frozen.is_some(), "PROD froze on the notice");
    // While frozen, PROD refuses requests and COLD refuses jobs.
    assert!(w.withdraw(DEST, 1, PATH).await.is_err());
    // Recovery needs a quorum Unfreeze; a replayed Unfreeze is refused.
    let u = w.unfreeze();
    assert!(w.cold.apply_quorum(&u, w.now).is_err(), "old Unfreeze cannot be replayed");
    let j = w.withdraw(DEST, 1, PATH).await.unwrap();
    assert_eq!(w.status_of(j).unwrap().outcome, Outcome::Signed);
}

#[tokio::test(flavor = "multi_thread")]
async fn compromised_prod_cannot_swap_the_request() {
    let mut w = ready().await;
    // PROD rewrites the envelope's raw_tx: UPSTREAM's signature no longer verifies at COLD.
    let good = w.tx(DEST, ETH);
    let evil = w.tx(DEST, 2 * ETH);
    let (_, env) = w.envelope(good, PATH);
    let mut f: SignedMsg = decode_canonical(&env).unwrap();
    let mut e: WithdrawalEnvelope = decode_canonical(&f.body.0).unwrap();
    e.raw_tx = Bytes(evil.clone());
    f.body = Bytes(chp_wire::encode(&e));
    let swapped = chp_wire::encode(&f);
    let id = first_id(&w);
    let (job, frags) = craft(&mut w, &swapped, &evil, id, &evil);
    let seq = job.job_seq;
    w.prod.adversary_send_job(job, &frags);
    w.pump().await;
    let st = w.status_of(seq).unwrap();
    assert_eq!(st.outcome, Outcome::Rejected);
    assert!(st.reason.contains("UPSTREAM signature"), "{}", st.reason);
    assert!(w.broadcasts.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn ssid_mismatch_is_rejected_and_burned() {
    let mut w = ready().await;
    let good = w.tx(DEST, ETH);
    let other = w.tx(DEST, 3);
    let (_, env) = w.envelope(good.clone(), PATH);
    let id = first_id(&w);
    let (job, frags) = craft(&mut w, &env, &good, id, &other);
    let seq = job.job_seq;
    w.prod.adversary_send_job(job, &frags);
    w.pump().await;
    let st = w.status_of(seq).unwrap();
    assert_eq!(st.outcome, Outcome::Rejected);
    assert!(st.reason.contains("ssid"), "{}", st.reason);
    assert!(!frozen(&w));
    assert!(!w.cold.pool(&w.pool(PATH)).unwrap().halves.contains_key(&id), "burned at COLD");
}

#[tokio::test(flavor = "multi_thread")]
async fn reused_and_never_issued_presignatures_freeze() {
    let mut w = ready().await;
    let j = w.withdraw(DEST, 1, PATH).await.unwrap();
    assert_eq!(w.status_of(j).unwrap().outcome, Outcome::Signed);
    let used = w.cold.pool(&w.pool(PATH)).unwrap().high_water;

    // A PROD that kept a copy of a used half (or was rolled back) replays its id.
    let raw = w.tx(DEST, 1);
    let (_, env) = w.envelope(raw.clone(), PATH);
    let next = first_id(&w);
    let (mut job, frags) = craft(&mut w, &env, &raw, next, &raw);
    job.items[0].presig_id = used;
    job.items[0].ssid = ssid(CHAIN, &w.key_id, 1, used, &chp_chain::decode(CHAIN, &raw).unwrap().messages[0], PATH);
    let seq = job.job_seq;
    w.prod.adversary_send_job(job, &frags);
    w.pump().await;
    assert_eq!(w.status_of(seq).unwrap().outcome, Outcome::Fault(Fault::PresigState));
    assert!(frozen(&w));

    // An id COLD never issued also freezes.
    let mut w = ready().await;
    let raw = w.tx(DEST, 1);
    let (_, env) = w.envelope(raw.clone(), PATH);
    let id = first_id(&w);
    let (mut job, frags) = craft(&mut w, &env, &raw, id, &raw);
    let bogus = presig_id::make(0, 0, 999, 0);
    job.items[0].presig_id = bogus;
    let seq = job.job_seq;
    w.prod.adversary_send_job(job, &frags);
    w.pump().await;
    assert_eq!(w.status_of(seq).unwrap().outcome, Outcome::Fault(Fault::PresigState));
}

#[tokio::test(flavor = "multi_thread")]
async fn tampered_fragment_ciphertext_is_a_prod_fault() {
    let mut w = ready().await;
    let raw = w.tx(DEST, 1);
    let (_, env) = w.envelope(raw.clone(), PATH);
    let id = first_id(&w);
    let (job, _frags) = craft(&mut w, &env, &raw, id, &raw);
    let mut job = job;
    job.sealed = Sealed { enc: Bytes(vec![7; 32]), ct: Bytes(vec![1; 64]) };
    let seq = job.job_seq;
    w.prod.adversary_send_job_raw(job);
    w.pump().await;
    assert_eq!(w.status_of(seq).unwrap().outcome, Outcome::Fault(Fault::ProdFragment));
    assert!(frozen(&w));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resent_job_is_never_signed_twice() {
    let mut w = ready().await;
    let raw = w.tx(DEST, 1);
    let (_, env) = w.envelope(raw, PATH);
    w.prod.withdraw(&env, w.now).unwrap();
    // capture the Job body before it is delivered
    let job_frame = w.prod.out.iter().find_map(|o| match o {
        Out::Send { bytes, .. } => Some(bytes.clone()),
        _ => None,
    }).unwrap();
    let f: SignedMsg = decode_canonical(&job_frame).unwrap();
    let job: Job = decode_canonical(&f.body.0).unwrap();
    w.pump().await;
    assert_eq!(signed_count(&w), 1);
    let first = w.cold.st.jobs[&job.job_seq].1.clone();

    // The identical job again (e.g. after a reconnect): COLD returns the stored Status.
    w.prod.adversary_send_job_raw(job.clone());
    w.pump().await;
    assert_eq!(signed_count(&w), 1, "never signed twice");
    assert_eq!(w.cold.st.jobs[&job.job_seq].1, first);

    // Same job_seq, different content: refused.
    let mut j2 = job.clone();
    j2.prod_time += 1;
    w.prod.adversary_send_job_raw(j2);
    w.pump().await;
    assert_eq!(signed_count(&w), 1);
    assert!(w.cold.events.iter().any(|e| matches!(e, Event::Refused { why, .. } if why.contains("job_seq reused"))));
}

#[tokio::test(flavor = "multi_thread")]
async fn time_sources_must_agree() {
    let mut w = ready().await;
    let raw = w.tx(DEST, 1);
    let (_, env) = w.envelope(raw.clone(), PATH);
    let id = first_id(&w);
    let (mut job, frags) = craft(&mut w, &env, &raw, id, &raw);
    job.prod_time = w.now + 10_000; // PROD's clock disagrees with UPSTREAM's
    let seq = job.job_seq;
    w.prod.adversary_send_job(job, &frags);
    w.pump().await;
    let st = w.status_of(seq).unwrap();
    assert_eq!(st.outcome, Outcome::Rejected);
    assert!(st.reason.contains("time"), "{}", st.reason);
    let _ = B32::default();
}
