//! CHP demo: every party, every sub-protocol, every message.
//!
//!     cargo run -p chp-sim --example demo
//!
//! Each step names the sub-protocol (DESIGN.md SP1–SP10). Every frame between parties is
//! printed as `FROM → TO  Type (stream, seq)`; refusals, freezes and batch changes are printed
//! as the engines record them.

use chp_auth::{sign_body, trust::Trust};
use chp_core::{address::{verify_proof, Asked}, digest::ssid};
use chp_crypto::{derive::t_path, ecdsa::prod_fragment, ident::IdKey};
use chp_sim::{trace, *};
use chp_wire::{decode_canonical, msgs::*, Bytes, MsgType, Role, B32};

const ETH: u128 = 1_000_000_000_000_000_000;
const ATTACKER: &str = "0x6666666666666666666666666666666666666666";

fn step(n: &str, title: &str) {
    println!("\n━━ {n} · {title} {}", "━".repeat(80usize.saturating_sub(title.len() + n.len())));
    trace::step(n, title);
}
fn note(s: &str) {
    println!("  ▸ {s}");
    trace::note(s);
}

fn book_address(w: &World, path: &str) -> String {
    let b: AddressBook = w.prod.trust.verify_quorum(&w.book, MsgType::AddressBook).unwrap();
    b.entries.iter().find(|e| e.path == path).unwrap().address.clone()
}

async fn wake_and_presign(w: &mut World, batches: u32, why: &str) {
    note(&format!("operators at COLD and at HOT agree to wake HOT ({why})"));
    w.hot_boot();
    let counter = w.hot.wake_counter();
    note(&format!("HOT powers on LOCKED and shows its hardware wake counter = {counter}"));
    w.pump().await;
    w.connect_hot();
    let digest = w.cold.open_wake(w.key_id, 1, ReturnStage::PresignSync, batches, w.now + 600, counter);
    note(&format!("COLD → HOT WakeOpen{{PresignSync, max_batches {batches}, wake_seq {}}}", counter + 1));
    w.pump().await;
    note("HOT checks: mode allows PresignSync ✔ key active ✔ caps ✔ wake_seq == counter+1 ✔ → counter advanced");
    note("operator at HOT compares the digest on HOT's screen with COLD's screen → match");
    w.hot.operator_confirm_wake(digest).unwrap();
    w.pump().await;
    note("operator at COLD confirms → window OPEN; COLD relays pending quorum files (RosterUpdate first)");
    w.cold.operator_confirm_wake().unwrap();
    w.pump().await;
    for i in 0..batches {
        note(&format!("SP4 batch {}: COLD allocates ids above the pool's high-water mark in a fresh counter block", i + 1));
        w.cold.start_batch(PATH, w.now).unwrap();
        w.pump().await;
    }
    w.cold.close_wake("refill done");
    w.pump().await;
    w.hot_off();
    w.cold.link_lost(Role::Hot);
    note("window closed: HOT erased all session state and POWERED OFF (it holds no halves)");
}

async fn carry(w: &mut World) {
    note(&format!("an operator (not PROD's custodian) carries {} bundle(s) on removable media to PROD", w.media.len()));
    for b in std::mem::take(&mut w.media) {
        trace::msg("MEDIA", "PROD", "MediaBundle", "carried by hand, imported", "media");
        note("PROD imports: HOT cert ✔ signature ✔ seq 0 ✔ HPKE open ✔ recompute digest ✔ ids above high-water ✔ → Pending");
        w.prod.import_media(&b, w.now).unwrap();
        w.pump().await;
    }
    note("COLD activates each batch only because own digest == HOT's export digest == PROD's import digest");
}

async fn withdraw(w: &mut World, value: u128, label: &str) -> u64 {
    let raw = w.tx(DEST, value);
    let (rid, env) = w.envelope(raw, PATH);
    note(&format!("UPSTREAM signs WithdrawalEnvelope{{request {}, {label}, path {PATH}, not_after +120s}}", hex::encode(&rid.0[..4])));
    note("PROD admission (no state change on refusal): UPSTREAM sig ✔ fresh ✔ not replayed ✔ key active ✔ own decode ✔ own policy ✔ halves available ✔");
    trace::msg("UPSTREAM", "PROD", "WithdrawalEnvelope", label, "api");
    let job = w.prod.withdraw(&env, w.now).expect("admitted");
    note("PROD takes the next half (deleted BEFORE computing), computes ssid + 96-byte fragment, HPKE-seals it to COLD");
    w.pump().await;
    job
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    trace::enable();
    let json_out = std::env::args().skip_while(|a| a != "--json").nth(1);
    println!("╔══════════════════════════════════════════════════════════════════════════════════╗");
    println!("║  COLD-HOT-PROD (CHP) demo — prototype / reference implementation (simulated TEE) ║");
    println!("║  Parties: HOT (offline share) · COLD (share, only signer) · PROD (online, no share)║");
    println!("║           REC (backup HSM share) · quorums · UPSTREAM · requester · chain        ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════════╝");

    // ------------------------------------------------------------------ make the key
    let mut w = World::setup(Options { narrate: true, ..Default::default() }).await;
    note(&format!("hot address for {PATH}: {}", book_address(&w, PATH)));

    // ------------------------------------------------------------------ presign + media
    step("SP4", "HOT wake window: presign batches with COLD");
    wake_and_presign(&mut w, 2, "pool is empty").await;
    step("SP5", "Media transfer HOT → 💾 → PROD, then activation");
    carry(&mut w).await;
    note(&format!("pool {PATH}: PROD holds {} active halves, COLD holds its matching {}", w.prod.available(&w.pool(PATH)), w.cold.pool(&w.pool(PATH)).unwrap().active_ids().len()));

    // ------------------------------------------------------------------ sign
    step("SP6", "Online signing: one message PROD → COLD");
    let job = withdraw(&mut w, ETH, "1 ETH to the allowlisted address").await;
    let st = w.status_of(job).unwrap();
    note("COLD: burn first (high-water mark + hardware counter), then re-checks EVERYTHING itself:");
    note("      UPSTREAM sig ✔ two signed times agree ✔ not expired ✔ own decode ✔ ssid recomputed ✔ path in book ✔ COLD policy ✔");
    note("      combine fragment + own half → ECDSA signature → verified with libsecp256k1 (independent of the MPC library)");
    assert_eq!(st.outcome, Outcome::Signed, "{}", st.reason);
    note(&format!("Status = {:?}", st.outcome));
    let sender = recover_sender(&w.broadcasts.last().unwrap().1);
    note(&format!("signature recovers to {sender} == quorum-signed book address ✔ {}", sender == book_address(&w, PATH)));

    // ------------------------------------------------------------------ address proof
    step("SP10", "Address proof for a depositor, verified offline");
    let nonce = B32(rand::random());
    let request_id = B32(rand::random());
    let q = AddressQuery { request_id, chain: CHAIN.into(), address: None, path: Some(PATH.into()), nonce, not_after: w.now + 60 };
    let qf = sign_body(&w.requester, MsgType::AddressQuery, 0, &q);
    note("requester → PROD AddressQuery{path, nonce} (signed by the enrolled requester)");
    trace::msg("REQUESTER", "PROD", "AddressQuery", format!("path {PATH}"), "api");
    let proof = w.prod.address_query(&qf, w.now).unwrap();
    trace::msg("PROD", "REQUESTER", "AddressProof", "book + manifest + PROD sig", "api");
    note("PROD → requester AddressProof{entry, AddressBook, KeyManifest, PROD cert} signed by PROD");
    let pinned_only = Trust::new(&w.q.pinned());
    let e = verify_proof(&pinned_only, &proof, &Asked { request_id, nonce, chain: CHAIN, address: None, path: Some(PATH) }, 0, w.now).unwrap();
    note(&format!("requester verifies with the pinned roster only: quorum sigs ✔ address re-derived ✔ control sig by the key ✔ active ✔ → {}", e.address));

    // ------------------------------------------------------------------ attack + freeze
    step("SP7", "Attack: a compromised PROD tries to redirect funds → freeze");
    let good = w.tx(DEST, ETH);
    let evil = w.tx(ATTACKER, 9 * ETH);
    let (_, env) = w.envelope(good.clone(), PATH);
    note(&format!("UPSTREAM asked for 1 ETH → {DEST}; hacked PROD computes its fragment for 9 ETH → {ATTACKER}"));
    let pool = w.pool(PATH);
    let id = w.prod.held_ids(&pool)[0];
    let half = w.prod.adversary_take_half(&pool, id).unwrap();
    let y = w.prod.keyring.get(&w.key_id, 1).unwrap().group_key();
    let m_good = chp_chain::decode(CHAIN, &good).unwrap().messages[0];
    let m_evil = chp_chain::decode(CHAIN, &evil).unwrap().messages[0];
    let frag = prod_fragment(half, &m_evil, &t_path(&w.key_id.0, &y, PATH)).unwrap();
    let job = Job {
        job_seq: w.prod.adversary_bump_job_seq(),
        envelope: Bytes(env),
        key_version: 1,
        items: vec![JobItem { input: 0, presig_id: id, ssid: ssid(CHAIN, &w.key_id, 1, id, &m_good, PATH) }],
        prod_time: w.now,
        sealed: Sealed { enc: Bytes::default(), ct: Bytes::default() },
    };
    let seq = job.job_seq;
    trace::msg("UPSTREAM", "PROD", "WithdrawalEnvelope", "1 ETH → allowlisted", "api");
    trace::event("PROD", "COMPROMISED: fragment computed for 9 ETH → attacker", "fault");
    w.prod.adversary_send_job(job, &[frag]);
    w.pump().await;
    let st = w.status_of(seq).unwrap();
    note(&format!("COLD decodes UPSTREAM's tx itself; the combined signature fails verification → {:?}", st.outcome));
    note(&format!("broadcasts so far: {} (nothing invalid is ever broadcast)", w.broadcasts.len()));
    trace::msg("UPSTREAM", "PROD", "WithdrawalEnvelope", "new request while frozen", "api");
    let r = w.withdraw(DEST, 1, PATH).await;
    trace::event("PROD", "refused at admission: key frozen", "warn");
    note(&format!("while frozen, PROD refuses new requests: {}", r.unwrap_err()));
    note("investigation done → custodians sign Unfreeze{version 1} (M-of-N); each party verifies it itself");
    trace::msg("QUORUM", "COLD", "Unfreeze", "version 1 (M-of-N)", "quorum");
    trace::msg("QUORUM", "PROD", "Unfreeze", "version 1 (M-of-N)", "quorum");
    let u = w.unfreeze();
    w.flush_events();
    w.snap();
    note(&format!("replaying that Unfreeze is refused: {}", w.cold.apply_quorum(&u, w.now).is_err()));

    // ------------------------------------------------------------------ COLD restart
    step("§6.1", "COLD restart: hardware counter closes the open block");
    let before = w.prod.available(&pool);
    w.cold.boot();
    trace::event("COLD", "reboot: restore check ✔ → pool counter incremented, open block closed", "warn");
    note("COLD boots: per pool, sealed counter value vs hardware value (restore check) → increment counter");
    w.prod.link_lost();
    w.connect_prod();
    w.pump().await;
    note(&format!("PROD obeys OrphanDelete: available {before} → {} (rest of the open block burned, next batch intact)", w.prod.available(&pool)));
    let job = withdraw(&mut w, 2 * ETH, "2 ETH").await;
    let st = w.status_of(job).unwrap();
    assert_eq!(st.outcome, Outcome::Signed, "{}", st.reason);
    note(&format!("Status = {:?}", st.outcome));

    // ------------------------------------------------------------------ EXIT: PROD
    step("EXIT", "PROD leaves: quorum revokes it (SP1 §8, SP8 §3)");
    let old_prod_cert = w.prod.cert().to_vec();
    note("custodians sign RevocationList{version 1, [SHA-256(PROD id_pk)]}");
    w.revoke_prod();
    note("COLD: revoked key dropped from every keyring, link closed, EVERY presignature pool discarded");
    note("no key ceremony needed: PROD never held a key share");
    let tls = B32([9; 32]);
    let (n, h) = w.cold.dial(tls);
    let reply = w.prod.on_hello(&h, tls, w.now).unwrap();
    trace::msg("PROD", "COLD", "LinkHello", "old PROD tries to come back", "fault");
    trace::event("COLD", "refused LinkHello: revoked", "warn");
    note(&format!("old PROD tries to link again → COLD refuses: {}", w.cold.on_hello_reply(&reply, tls, n, w.now).unwrap_err()));
    let _ = old_prod_cert;

    // ------------------------------------------------------------------ JOIN: new PROD
    step("JOIN", "A new PROD joins: enroll, public data, link, refill");
    w.join_new_prod();
    note("new PROD enclave attested → quorum signs its PartyCert; it receives manifest, book, Activate, policy (public only)");
    note("COLD queued for HOT: RevocationList + the new PROD's PartyCert (HOT must seal bundles to the NEW PROD)");
    wake_and_presign(&mut w, 1, "deliver quorum files to HOT and refill for the new PROD").await;
    carry(&mut w).await;
    let n0 = w.broadcasts.len();
    let job = withdraw(&mut w, ETH, "1 ETH via the new PROD").await;
    let st = w.status_of(job).expect("COLD answered the new PROD");
    note(&format!("Status = {:?} for the new PROD's job_seq {job} (COLD keys jobs by PROD identity + job_seq)", st.outcome));
    assert_eq!(st.outcome, Outcome::Signed, "{}", st.reason);
    assert_eq!(w.broadcasts.len(), n0 + 1);
    note("broadcast by the new PROD ✔");

    // ------------------------------------------------------------------ JOIN: requester
    step("JOIN", "A new auditor joins as an address-proof requester");
    let auditor = IdKey::generate(&mut rand::thread_rng());
    let cert = w.q.enroll_client(Role::Requester, auditor.public(), w.now, 86_400);
    w.prod.apply_quorum(&cert, w.now).unwrap();
    trace::msg("QUORUM", "REQUESTER", "PartyCert", "new auditor (role Requester)", "quorum");
    trace::msg("QUORUM", "PROD", "PartyCert (auditor)", "enrolled requester", "quorum");
    note("quorum signs PartyCert{role Requester}; PROD enrolls it");
    let nonce = B32(rand::random());
    let request_id = B32(rand::random());
    let addr2 = book_address(&w, PATH2);
    let q = AddressQuery { request_id, chain: CHAIN.into(), address: Some(addr2.clone()), path: None, nonce, not_after: w.now + 60 };
    let proof = w.prod.address_query(&sign_body(&auditor, MsgType::AddressQuery, 0, &q), w.now).unwrap();
    trace::msg("REQUESTER", "PROD", "AddressQuery", "auditor: hot address 2", "api");
    trace::msg("PROD", "REQUESTER", "AddressProof", "verifies offline", "api");
    let ok = verify_proof(&pinned_only, &proof, &Asked { request_id, nonce, chain: CHAIN, address: Some(&addr2), path: None }, 0, w.now).is_ok();
    note(&format!("auditor asks about {} → proof verifies offline: {ok}", book_address(&w, PATH2)));
    let q2 = AddressQuery { request_id: B32(rand::random()), chain: CHAIN.into(), address: Some(ATTACKER.into()), path: None, nonce: B32(rand::random()), not_after: w.now + 60 };
    let nf = w.prod.address_query(&sign_body(&auditor, MsgType::AddressQuery, 0, &q2), w.now).unwrap();
    trace::msg("REQUESTER", "PROD", "AddressQuery", "auditor: attacker's address", "api");
    trace::msg("PROD", "REQUESTER", "NotFound", "signed: not ours", "api");
    let f: chp_wire::SignedMsg = decode_canonical(&nf).unwrap();
    note(&format!("auditor asks about {ATTACKER} → {:?} (never \"probably ours\")", MsgType::from_code(f.msg_type).unwrap()));

    // ------------------------------------------------------------------ share holder exit
    step("EXIT", "A share holder (HOT / COLD / REC) is lost: sweep, never repair (SP8 §4)");
    note("outside CHP, by design: the two surviving share holders sign a sweep of all funds to a");
    note("pre-registered cold-wallet address in a quorum-opened offline ceremony (no presignatures),");
    note("then a NEW key is made from scratch (SP2) with new enclaves for the suspect party.");
    note("HOT lost → COLD + REC sign · COLD lost → HOT + REC sign · REC lost → HOT + COLD sign");

    // ------------------------------------------------------------------ summary
    step("DONE", "Summary");
    note(&format!("withdrawals broadcast: {}", w.broadcasts.len()));
    for (_, tx, txid) in &w.broadcasts {
        note(&format!("  txid {}  from {}", hex::encode(&txid.0[..8]), recover_sender(tx)));
    }
    note("the full private key never existed; PROD never held a share; every frame was signed,");
    note("sequence-checked and role-checked before it was parsed.");
    w.snap();
    if let Some(path) = json_out {
        let items = trace::take();
        std::fs::write(&path, serde_json::to_string_pretty(&items).unwrap()).unwrap();
        println!("\ntrace written to {path} ({} items)", items.len());
    }
}
