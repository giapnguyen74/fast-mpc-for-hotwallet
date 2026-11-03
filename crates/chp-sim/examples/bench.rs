//! CHP benchmarks.
//!
//!     cargo run --release -p chp-sim --example bench [-- --md docs/BENCHMARKS.md]
//!
//! Single-threaded crypto timings per input, multi-party MPC runs in-process, and protocol
//! operations end to end through the simulator (framing, signatures, HPKE, policy, decode).
//! The simulator moves bytes in memory: there is no network latency in these numbers.

use std::time::{Duration, Instant};

use chp_auth::sign_msg;
use chp_crypto::{
    derive::{derived_key, t_path},
    ecdsa::{cold_complete, prod_fragment},
    ident::{self, IdKey},
    seal::{seal, WrapKey},
};
use chp_mpc::{
    dkls::{local_dkg, local_mesh, local_presign, presign_instance, refresh},
    half_from_presign,
};
use chp_sim::*;
use chp_wire::{msgs::*, MsgType, B32};
use std::sync::Arc;

struct Row {
    group: &'static str,
    name: String,
    n: usize,
    median: Duration,
    p95: Duration,
    note: String,
}

fn row(group: &'static str, name: &str, mut v: Vec<Duration>, note: &str) -> Row {
    v.sort();
    let n = v.len();
    let median = v[n / 2];
    let p95 = v[((n as f64) * 0.95).ceil() as usize - 1];
    let r = Row { group, name: name.into(), n, median, p95, note: note.into() };
    eprintln!("  {:<52} median {:>10}  p95 {:>10}  (n={n})", r.name, fmt(r.median), fmt(r.p95));
    r
}

fn fmt(d: Duration) -> String {
    let us = d.as_secs_f64() * 1e6;
    if us < 1000.0 {
        format!("{us:.1} µs")
    } else if us < 1e6 {
        format!("{:.2} ms", us / 1000.0)
    } else {
        format!("{:.2} s", us / 1e6)
    }
}

fn time<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let t = Instant::now();
    let r = f();
    (r, t.elapsed())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let md_out = std::env::args().skip_while(|a| a != "--md").nth(1);
    let mut rows = Vec::new();
    let key_id = b"bench-key";

    // ------------------------------------------------------------ A. online-path crypto
    eprintln!("A. online signing path, per input (single thread)");
    let shares: Vec<_> = local_dkg(rand::random()).await.unwrap().into_iter().map(Arc::new).collect();
    let y = shares[0].public_key();
    let path = "m/hot/0";
    let t = t_path(key_id, &y, path);
    let yp = derived_key(key_id, &y, path);
    const N: usize = 300;
    let mut pairs = Vec::new();
    let mut presign_t = Vec::new();
    for i in 0..N {
        let ((pa, pb), d) = {
            let s = Instant::now();
            let r = local_presign(shares[0].clone(), shares[1].clone(), presign_instance(&[7; 32], i as u64)).await.unwrap();
            (r, s.elapsed())
        };
        presign_t.push(d);
        pairs.push((half_from_presign(&pa), half_from_presign(&pb)));
    }
    let mut frag_t = Vec::new();
    let mut comb_t = Vec::new();
    for (h, c) in pairs {
        let m: [u8; 32] = rand::random();
        let (f, d) = time(|| prod_fragment(h, &m, &t).unwrap());
        frag_t.push(d);
        let (_, d) = time(|| cold_complete(c, &f, &m, &t, &yp).unwrap());
        comb_t.push(d);
    }
    rows.push(row("A", "DKLs23 · PROD fragment (s₀_h, s₁_h)", frag_t, "DESIGN SP6 §7 estimate ~15 µs"));
    rows.push(row("A", "DKLs23 · COLD combine + low-s + libsecp256k1 verify", comb_t, "estimate ~160 µs"));

    {
        use chp_frost::{dkg::*, secp, taproot::TaprootKey};
        use frost_secp256k1_tr::{Identifier, Secp256K1Sha256TR as S};
        let mut rng = rand::thread_rng();
        let ids3 = [Identifier::try_from(1u16).unwrap(), Identifier::try_from(2u16).unwrap(), Identifier::try_from(3u16).unwrap()];
        let out = run_dkg_2of3::<S, _>(ids3, &mut rng).unwrap();
        let hot = secp_party(&out.key_packages[&ids3[0]]).unwrap();
        let cold = secp_party(&out.key_packages[&ids3[1]]).unwrap();
        let yk = secp_group_key(&out.public).unwrap();
        let y_h = secp_verifying_share(&out.public, &ids3[0]).unwrap();
        let ids = secp::SignerIds::new(hot.id, cold.id).unwrap();
        let key = TaprootKey::derive(key_id, &yk, path).unwrap();
        let (mut pf, mut cf) = (Vec::new(), Vec::new());
        for _ in 0..N {
            let msg: [u8; 32] = rand::random();
            let (n_h, com_h) = secp::hot_presign_nonces(&mut rng);
            let (n_c, com_c) = secp::presign_nonces(&mut rng);
            let (sp, delta) = secp::split_share(&hot.share, &mut rng);
            let (z, d) = time(|| {
                let s = secp::Session::new(&key, ids, &msg, com_h, com_c).unwrap();
                secp::prod_fragment(&s, n_h, &sp)
            });
            pf.push(d);
            let (_, d) = time(|| {
                let s = secp::Session::new(&key, ids, &msg, com_h, com_c).unwrap();
                secp::cold_complete(&s, &z, n_c, &cold.share, &delta, &y_h).unwrap()
            });
            cf.push(d);
        }
        rows.push(row("A", "FROST-Taproot · PROD fragment z_h (incl. session)", pf, "estimate ~140 µs"));
        rows.push(row("A", "FROST-Taproot · COLD check + combine + BIP340 verify", cf, "estimate ~400 µs"));
    }
    {
        use chp_frost::{dkg::*, ed25519 as ed};
        use frost_ed25519::{Ed25519Sha512 as E, Identifier};
        let mut rng = rand::thread_rng();
        let ids3 = [Identifier::try_from(1u16).unwrap(), Identifier::try_from(2u16).unwrap(), Identifier::try_from(3u16).unwrap()];
        let out = run_dkg_2of3::<E, _>(ids3, &mut rng).unwrap();
        let hot = ed_party(&out.key_packages[&ids3[0]]).unwrap();
        let cold = ed_party(&out.key_packages[&ids3[1]]).unwrap();
        let yk = ed_group_key(&out.public).unwrap();
        let y_h = ed_verifying_share(&out.public, &ids3[0]).unwrap();
        let ids = ed::SignerIds::new(hot.id, cold.id).unwrap();
        let key = ed::Ed25519Key::derive(key_id, &yk, "m").unwrap();
        let (mut pf, mut cf) = (Vec::new(), Vec::new());
        for _ in 0..N {
            let msg: [u8; 32] = rand::random();
            let (n_h, com_h) = ed::hot_presign_nonces(&mut rng);
            let (n_c, com_c) = ed::presign_nonces(&mut rng);
            let (sp, delta) = ed::split_share(&hot.share, &mut rng);
            let (z, d) = time(|| {
                let s = ed::Session::new(&key, ids, &msg, com_h, com_c).unwrap();
                ed::prod_fragment(&s, n_h, &sp)
            });
            pf.push(d);
            let (_, d) = time(|| {
                let s = ed::Session::new(&key, ids, &msg, com_h, com_c).unwrap();
                ed::cold_complete(&s, &z, n_c, &cold.share, &delta, &y_h).unwrap()
            });
            cf.push(d);
        }
        rows.push(row("A", "FROST-Ed25519 · PROD fragment z_h (incl. session)", pf, "estimate ~70 µs"));
        rows.push(row("A", "FROST-Ed25519 · COLD check + combine + strict verify", cf, "estimate ~240 µs"));
    }
    {
        let mut rng = rand::thread_rng();
        let wk = WrapKey::generate(&mut rng);
        let pt = [5u8; 96];
        let (mut st, mut ot) = (Vec::new(), Vec::new());
        for _ in 0..N {
            let (s, d) = time(|| seal(&wk.public(), b"chp-job-v1", b"aad", &pt, &mut rng).unwrap());
            st.push(d);
            let (_, d) = time(|| wk.open(&s, b"chp-job-v1", b"aad").unwrap());
            ot.push(d);
        }
        rows.push(row("A", "HPKE seal, 96-byte fragment (X25519/ChaCha20-Poly1305)", st, "PROD → COLD"));
        rows.push(row("A", "HPKE open, 96-byte fragment", ot, "at COLD"));
    }

    // ------------------------------------------------------------ B. SP1
    eprintln!("B. SP1 authentication");
    {
        let id = IdKey::generate(&mut rand::thread_rng());
        let body = chp_wire::encode(&FreezeNotice { key_id: B32([1; 32]), key_version: 1, fault: chp_wire::Fault::FinalVerify, evidence_hash: B32([2; 32]) });
        let (mut s, mut v) = (Vec::new(), Vec::new());
        for i in 0..N {
            let (f, d) = time(|| chp_wire::encode(&sign_msg(&id, MsgType::FreezeNotice, i as u64, body.clone())));
            s.push(d);
            let pk = id.public();
            let (_, d) = time(|| {
                let fr: chp_wire::SignedMsg = chp_wire::decode_canonical(&f).unwrap();
                ident::verify(&pk, &chp_auth::signed_msg_input(fr.msg_type, fr.seq, &fr.body.0), &fr.sig.0).unwrap();
                chp_wire::msgs::validate(MsgType::FreezeNotice, &fr.body.0).unwrap();
            });
            v.push(d);
        }
        rows.push(row("B", "sign a frame (Ed25519 + deterministic CBOR)", s, ""));
        rows.push(row("B", "check a frame (decode, signature, canonical body)", v, "steps 1–6 cost"));
    }

    // ------------------------------------------------------------ C. MPC ceremonies / presign
    eprintln!("C. MPC (in-process, multi-party)");
    let mut dkg_t = Vec::new();
    for _ in 0..10 {
        let (_, d) = {
            let s = Instant::now();
            let r = local_dkg(rand::random()).await.unwrap();
            (r, s.elapsed())
        };
        dkg_t.push(d);
    }
    rows.push(row("C", "DKLs23 DKG 2-of-3 (3 parties, in-process)", dkg_t, "MPC rounds only"));
    rows.push(row("C", "DKLs23 presign, one presignature (2 parties)", presign_t, "R1–R3 incl. OT multiplication"));
    let mut ref_t = Vec::new();
    for _ in 0..5 {
        let (relays, pump) = local_mesh(3);
        let s = Instant::now();
        let mut set = tokio::task::JoinSet::new();
        let inst: [u8; 32] = rand::random();
        for (sh, r) in shares.iter().cloned().zip(relays) {
            set.spawn(async move { refresh(&sh, inst, rand::random(), r).await });
        }
        while let Some(r) = set.join_next().await {
            r.unwrap().unwrap();
        }
        ref_t.push(s.elapsed());
        pump.abort();
    }
    rows.push(row("C", "DKLs23 key refresh (3 parties)", ref_t, "SP8 primitive"));

    // ------------------------------------------------------------ D. protocol, end to end
    eprintln!("D. protocol through the simulator (all checks, framing, HPKE)");
    let mut setup_t = Vec::new();
    let mut w = None;
    for _ in 0..3 {
        let (ww, d) = {
            let s = Instant::now();
            let r = World::setup(Options { batch_size: 64, ..Default::default() }).await;
            (r, s.elapsed())
        };
        setup_t.push(d);
        w = Some(ww);
    }
    rows.push(row("D", "SP1–SP3: enroll + DKG ceremony + test sigs + 2-address book + share delivery + activate", setup_t, "whole ceremony"));
    let mut w = w.unwrap();
    let mut win_t = Vec::new();
    for _ in 0..3 {
        let s = Instant::now();
        w.presign_window(PATH, 1).await;
        win_t.push(s.elapsed() / 64);
    }
    rows.push(row("D", "SP4 presign window, per presignature (batch of 64, framed + checked)", win_t, "amortised"));
    let mut imp_t = Vec::new();
    for b in std::mem::take(&mut w.media) {
        let s = Instant::now();
        w.prod.import_media(&b, w.now).unwrap();
        imp_t.push(s.elapsed());
        w.pump().await;
    }
    rows.push(row("D", "SP5 PROD import of one bundle (64 halves: verify, HPKE, digest)", imp_t, ""));
    let (mut adm_t, mut cold_t, mut rt_t) = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..150 {
        let raw = w.tx(DEST, 1);
        let (_, env) = w.envelope(raw, PATH);
        let s = Instant::now();
        let job = w.prod.withdraw(&env, w.now).unwrap();
        let a = s.elapsed();
        w.pump().await;
        let total = s.elapsed();
        assert_eq!(w.status_of(job).unwrap().outcome, Outcome::Signed);
        adm_t.push(a);
        cold_t.push(total - a);
        rt_t.push(total);
    }
    rows.push(row("D", "SP6 PROD: admission + take half + fragment + seal + sign Job", adm_t, "decode, policy, ssid"));
    rows.push(row("D", "SP6 COLD: frame check → burn → re-verify → combine → verify → Status → PROD broadcast", cold_t, "in-memory transport"));
    rows.push(row("D", "SP6 withdrawal round trip, one input (no network)", rt_t, "design target p99 < 100 ms incl. one hop"));
    let (mut pq, mut vq) = (Vec::new(), Vec::new());
    let verifier = chp_auth::trust::Trust::new(&w.q.pinned());
    for _ in 0..100 {
        let nonce = B32(rand::random());
        let request_id = B32(rand::random());
        let q = AddressQuery { request_id, chain: CHAIN.into(), address: None, path: Some(PATH.into()), nonce, not_after: w.now + 60 };
        let asked = chp_core::address::Asked { request_id, nonce, chain: CHAIN, address: None, path: Some(PATH) };
        let qf = chp_auth::sign_body(&w.requester, MsgType::AddressQuery, 0, &q);
        let (proof, d) = time(|| w.prod.address_query(&qf, w.now).unwrap());
        pq.push(d);
        let (_, d) = time(|| chp_core::address::verify_proof(&verifier, &proof, &asked, 0, w.now).unwrap());
        vq.push(d);
    }
    rows.push(row("D", "SP10 PROD answers AddressQuery (signed proof)", pq, ""));
    rows.push(row("D", "SP10 requester verifies proof offline (quorum sigs, derivation, control sig)", vq, ""));

    // ------------------------------------------------------------ output
    let mut md = String::new();
    md.push_str("| Group | Operation | Median | p95 | n | Note |\n|---|---|---:|---:|---:|---|\n");
    for r in &rows {
        md.push_str(&format!("| {} | {} | {} | {} | {} | {} |\n", r.group, r.name, fmt(r.median), fmt(r.p95), r.n, r.note));
    }
    println!("{md}");
    if let Some(p) = md_out {
        std::fs::write(&p, &md).unwrap();
        eprintln!("written to {p}");
    }
}
