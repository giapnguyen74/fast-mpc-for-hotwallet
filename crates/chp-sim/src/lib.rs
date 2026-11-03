//! In-process simulator of a full CHP deployment (PLAN phase 1 `chp-sim`).
//!
//! [`World`] holds every party (HOT, COLD, PROD engines; REC's HSM; the quorums; UPSTREAM and a
//! requester), a simulated clock, the removable media in transit and a broadcast log standing in
//! for the chain. It moves bytes between engines exactly as the deployment would: links for
//! COLD→HOT and COLD→PROD, media for HOT→PROD, API calls into PROD.

pub mod trace;

use chp_auth::sign_body;
use chp_ceremony::{check_receipt, run_dkg, DkgOutput, Quorum, Recipients, RecHsm};
use chp_chain::evm::Eip1559;
use chp_core::Out;
use chp_crypto::ident::IdKey;
use chp_engine_cold::{Cold, ColdConfig};
use chp_engine_hot::{Hot, HotConfig, Mode};
use chp_engine_prod::Prod;
use chp_tee::{measurement_of, Enclave};
use chp_wire::{
    decode_canonical,
    msgs::*,
    Bytes, KeyId, MsgType, PoolId, Role, B32,
};

pub const T0: u64 = 1_800_000_000;
pub const CHAIN: &str = "evm:31337";
pub const PATH: &str = "m/hot/0";
pub const PATH2: &str = "m/hot/1";
pub const DEST: &str = "0x1111111111111111111111111111111111111111";

pub struct World {
    pub now: u64,
    pub q: Quorum,
    pub hot: Hot,
    pub cold: Cold,
    pub prod: Prod,
    pub rec: Option<RecHsm>,
    pub upstream: IdKey,
    pub upstream_cert: Vec<u8>,
    pub requester: IdKey,
    pub requester_cert: Vec<u8>,
    pub key_id: KeyId,
    pub manifest: Vec<u8>,
    pub book: Vec<u8>,
    pub dkg: Option<DkgOutput>,
    /// Media bundles written by HOT, waiting for an operator to carry them.
    pub media: Vec<Vec<u8>>,
    /// Signed transactions PROD broadcast.
    pub broadcasts: Vec<(String, Vec<u8>, B32)>,
    pub tx_nonce: u64,
    pub unfreeze_ver: u64,
    pub revocation_ver: u64,
    pub last_revocation: Option<Vec<u8>>,
    /// Print every frame and engine event (the demo).
    pub trace: bool,
    ev_seen: [usize; 3],
    presign_msgs: usize,
    pub hot_on: bool,
    pub prod_revoked: bool,
    pub prod_gen: u32,
}

/// Narration helper: prints only when `on`.
pub fn say(on: bool, s: impl AsRef<str>) {
    if on {
        let s = s.as_ref();
        println!("{s}");
        let t = s.trim();
        if let Some(h) = t.strip_prefix("━━ ") {
            let h = h.trim_end_matches(['━', ' ']);
            let (id, title) = h.split_once(" · ").unwrap_or(("", h));
            trace::step(id, title);
        } else if !t.is_empty() && !is_frame_line(t) {
            trace::note(t.trim_start_matches("▸ "));
        }
    }
}

/// Lines that echo a frame, a display or a broadcast: the recorder has these as messages /
/// events already, so they are not repeated as narration.
fn is_frame_line(t: &str) -> bool {
    t.starts_with('[') || ["COLD ", "HOT ", "PROD "].iter().any(|p| t.starts_with(p) && (t.contains(" → ") || t.contains(" ⇄ ")))
}

fn frame_class(t: &str, detail: &str) -> &'static str {
    if t.starts_with("FreezeNotice") {
        "fault"
    } else if t.starts_with("QuorumFile") {
        "quorum"
    } else if detail.contains("stream A") {
        "link-a"
    } else if detail.contains("stream B") {
        "link-b"
    } else {
        "link-c"
    }
}

/// `"PresignOpen (B#3)"` for a signed link frame.
pub fn describe(bytes: &[u8]) -> String {
    match decode_canonical::<chp_wire::SignedMsg>(bytes) {
        Ok(f) => {
            let t = MsgType::from_code(f.msg_type);
            let stream = t.and_then(|t| t.stream()).map(|s| format!("{s:?}")).unwrap_or("-".into());
            format!("{:<16} (stream {stream}, seq {})", t.map(|t| format!("{t:?}")).unwrap_or("?".into()), f.seq)
        }
        Err(_) => "<undecodable>".into(),
    }
}

fn short(b: &B32) -> String {
    hex::encode(&b.0[..4])
}

fn describe_event(who: &str, e: &chp_core::Event) -> String {
    use chp_core::Event::*;
    let (text, level) = match e {
        Refused { what, why } => (format!("refused {what}: {why}"), "warn"),
        Frozen { fault, .. } => (format!("FROZE the key ({fault:?})"), "fault"),
        Unfrozen { .. } => ("unfroze the key (quorum Unfreeze verified)".to_string(), "ok"),
        BatchState { batch_id, state } => (format!("batch {} → {state}", short(batch_id)), "info"),
        PoolDiscarded { path, reason } => (format!("discarded pool {path}: {reason}"), "warn"),
        Signed { request_id, txid } => (format!("signed request {} → txid {}", short(request_id), short(txid)), "ok"),
        Info(s) => (s.clone(), "info"),
    };
    trace::event(who, text, level);
    match e {
        Refused { what, why } => format!("      ✗ {who} refused {what}: {why}"),
        Frozen { fault, .. } => format!("      ❄ {who} FROZE the key ({fault:?})"),
        Unfrozen { .. } => format!("      ☀ {who} unfroze the key (quorum Unfreeze verified)"),
        BatchState { batch_id, state } => format!("      • {who}: batch {} → {state}", short(batch_id)),
        PoolDiscarded { path, reason } => format!("      🗑 {who} discarded pool {path}: {reason}"),
        Signed { request_id, txid } => format!("      ✔ {who} signed request {} → txid {}", short(request_id), short(txid)),
        Info(s) => format!("      · {who}: {s}"),
    }
}

pub struct Options {
    pub mode: Mode,
    pub batch_size: u16,
    pub paths: Vec<&'static str>,
    /// Narrate setup and trace frames (the demo).
    pub narrate: bool,
    /// COLD's limit per tx (PROD's is 10 ETH); lets tests make the two policies differ.
    pub cold_max_per_tx: String,
}

impl Default for Options {
    fn default() -> Self {
        Options { mode: Mode::Standard, batch_size: 4, paths: vec![PATH, PATH2], narrate: false, cold_max_per_tx: "10000000000000000000".into() }
    }
}

pub fn policy_rules(max_per_tx: &str) -> PolicyRules {
    PolicyRules {
        max_per_tx: max_per_tx.into(),
        max_per_day: "100000000000000000000".into(),
        allowlist: vec![DEST.into()],
        chain_ids: vec![31337],
        allow_calldata: false,
        max_fee_per_tx: "1000000000000000000".into(),
    }
}

impl World {
    /// Enroll every party, run the DKG ceremony, deliver shares (SP3), activate, install
    /// policies and certificates, and link COLD → PROD.
    pub async fn setup(o: Options) -> World {
        let now = T0;
        let n = o.narrate;
        say(n, "\n━━ SP1 · Enrollment: every party gets a quorum-signed identity ━━━━━━━━━━━━━━━━━━━━━━━");
        let releases = vec![measurement_of("hot-1.0"), measurement_of("cold-1.0"), measurement_of("prod-1.0")];
        let q = Quorum::new(releases);
        let pinned = q.pinned();
        let he = Enclave::new(measurement_of("hot-1.0"));
        let ce = Enclave::new(measurement_of("cold-1.0"));
        let pe = Enclave::new(measurement_of("prod-1.0"));
        let ttl = 90 * 86_400;
        let hot_cert = q.enroll(&he.attest_keys(Role::Hot, 0), Role::Hot, 0, 0, he.id.public(), he.wrap.public(), now, ttl).unwrap();
        let cold_cert = q.enroll(&ce.attest_keys(Role::Cold, 0), Role::Cold, 1, 0, ce.id.public(), ce.wrap.public(), now, ttl).unwrap();
        let prod_cert = q.enroll(&pe.attest_keys(Role::Prod, 0), Role::Prod, 0, 0, pe.id.public(), pe.wrap.public(), now, ttl).unwrap();
        say(n, "  HOT, COLD, PROD each generate id_key (Ed25519) + wrap_key (X25519) inside their enclave");
        say(n, "  each sends an attestation binding H(role ‖ replica ‖ id_pk ‖ wrap_pk) to the ceremony quorum");
        say(n, "  quorum (3-of-5 custodians) checks vendor signature + measurement on the release list → signs PartyCert");
        if n {
            for p in ["HOT", "COLD", "PROD"] {
                trace::msg(p, "QUORUM", "attestation", "measurement + H(role‖replica‖id_pk‖wrap_pk)", "quorum");
            }
            for p in ["HOT", "COLD", "PROD"] {
                trace::msg("QUORUM", p, "PartyCert", "quorum-signed identity", "quorum");
            }
            trace::msg("QUORUM", "UPSTREAM", "PartyCert", "client: withdrawal service", "quorum");
            trace::msg("QUORUM", "REQUESTER", "PartyCert", "client: deposit service", "quorum");
        }
        let mut hot = Hot::new(HotConfig { mode: o.mode, replica: 0, max_batches_cap: 16, max_window_secs: 3600 }, he, &pinned);
        let mut cold = Cold::new(ColdConfig { batch_size: o.batch_size, ..Default::default() }, ce, &pinned);
        let mut prod = Prod::new(pe, &pinned, 0);
        hot.set_cert(hot_cert.clone());
        cold.set_cert(cold_cert.clone());
        prod.set_cert(prod_cert.clone());

        let upstream = IdKey::generate(&mut rand::thread_rng());
        let requester = IdKey::generate(&mut rand::thread_rng());
        let upstream_cert = q.enroll_client(Role::Upstream, upstream.public(), now, ttl);
        let requester_cert = q.enroll_client(Role::Requester, requester.public(), now, ttl);

        say(n, "  UPSTREAM (withdrawal service) and a deposit-service requester enrolled as clients");
        say(n, "\n━━ SP2 · Key ceremony (DKG) on the isolated ceremony network ━━━━━━━━━━━━━━━━━━━━━━━━━━");
        say(n, format!("  quorum signs CeremonyOpen{{kind Dkg, boot_seq: HOT={}, COLD=1, REC=1}}", hot.wake_counter() + 1));
        // ---- SP2 ceremony + SP3 delivery ----
        let hc: PartyCert = hot.trust.verify_quorum(&hot_cert, MsgType::PartyCert).unwrap();
        let cc: PartyCert = hot.trust.verify_quorum(&cold_cert, MsgType::PartyCert).unwrap();
        let dkg = run_dkg(
            &q,
            CHAIN,
            &o.paths,
            Recipients { hot_cert: &hot_cert, cold_cert: &cold_cert, hot: &hc, cold: &cc, hot_boot_seq: hot.wake_counter() + 1, cold_boot_seq: 1 },
            now,
        )
        .await
        .expect("dkg");
        assert!(dkg.fingerprints.iter().all(|f| *f == dkg.fingerprints[0]));
        if n {
            for p in ["HOT", "COLD", "REC"] {
                trace::msg("QUORUM", p, "CeremonyOpen", "kind Dkg, boot_seq", "quorum");
            }
            trace::msg("HOT", "COLD", "DKG rounds", "ceremony network", "presign");
            trace::msg("COLD", "REC", "DKG rounds", "ceremony network", "presign");
            trace::msg("REC", "HOT", "DKG rounds", "ceremony network", "presign");
            for p in ["HOT", "COLD", "REC"] {
                trace::msg(p, "QUORUM", "Y fingerprint", &dkg.fingerprints[0], "quorum");
            }
        }
        say(n, "  DKLs23 2-of-3 DKG among HOT, COLD, REC — no dealer, the full key never exists");
        say(n, format!("  Y fingerprints read aloud: HOT {}  COLD {}  REC {}  → equal", dkg.fingerprints[0], dkg.fingerprints[1], dkg.fingerprints[2]));
        say(n, "  test signatures with every pair {H,C} {H,R} {C,R} verified against Y");
        say(n, format!("  quorum signs KeyManifest{{key_id {}, version 1, Y, public shares}}", short(&dkg.key_id)));
        say(n, format!("  each address path signs its own control statement → quorum signs AddressBook v1 ({} entries)", o.paths.len()));
        say(n, "\n━━ SP3 · Share delivery: sealed packages → HOT, COLD (REC keeps its share in its HSM) ━━━━━━");
        hot.ceremony_boot(&dkg.open, now).expect("hot ceremony boot");
        cold.ceremony_boot(&dkg.open, now).expect("cold ceremony boot");
        let hr = hot.import_share(&dkg.manifest, &dkg.hot_package).expect("hot import");
        let cr = cold.import_share(&dkg.manifest, &dkg.cold_package).expect("cold import");
        let mh = chp_core::digest::hash_of(&dkg.manifest);
        let man: KeyManifest = hot.trust.verify_quorum(&dkg.manifest, MsgType::KeyManifest).unwrap();
        check_receipt(&hr, &hot_cert, &hc, &man, &mh).expect("hot receipt");
        check_receipt(&cr, &cold_cert, &cc, &man, &mh).expect("cold receipt");
        say(n, "  HOT, COLD: ceremony boot (boot_seq = counter + 1) → HPKE-open own package → check s_i·G == Y_i");
        if n {
            trace::msg("QUORUM", "HOT", "SharePackage", "HPKE(s_HOT → HOT.wrap_pk)", "quorum");
            trace::msg("QUORUM", "COLD", "SharePackage", "HPKE(s_COLD → COLD.wrap_pk)", "quorum");
            trace::msg("HOT", "QUORUM", "ShareReceipt", "s_i·G == Y_i ✔", "quorum");
            trace::msg("COLD", "QUORUM", "ShareReceipt", "s_i·G == Y_i ✔", "quorum");
        }
        say(n, "  HOT, COLD → quorum: signed ShareReceipt (public share, measurement, manifest hash) ✔");
        say(n, "  quorum signs Activate(key v1): key ACTIVE_PENDING → ACTIVE on HOT, COLD, PROD");
        if n {
            for p in ["HOT", "COLD", "PROD"] {
                trace::msg("QUORUM", p, "Activate", "key v1 → ACTIVE", "quorum");
            }
            trace::msg("QUORUM", "PROD", "KeyManifest + AddressBook", "public data only", "quorum");
            trace::msg("QUORUM", "UPSTREAM", "KeyManifest + AddressBook", "to verify address proofs", "quorum");
        }
        say(n, "  PROD receives public data only: manifest, AddressBook, Activate (it refuses any share)");
        let activate = q.sign(MsgType::Activate, &KeyControl { key_id: dkg.key_id, key_version: 1, version: 1 });
        for f in [&activate, &dkg.book, &prod_cert] {
            hot.apply_quorum_object(f, now).expect("hot quorum file");
        }
        hot.end_ceremony();
        cold.end_ceremony();
        cold.apply_quorum(&activate, now).unwrap();
        cold.apply_quorum(&dkg.book, now).unwrap();
        cold.apply_quorum(&upstream_cert, now).unwrap();
        cold.apply_quorum(&q.sign_policy(&PolicyBundle { target: Role::Cold, key_id: dkg.key_id, version: 1, rules: policy_rules(&o.cold_max_per_tx) }), now).unwrap();
        for f in [&dkg.manifest, &activate, &dkg.book, &upstream_cert, &requester_cert] {
            prod.apply_quorum(f, now).unwrap();
        }
        prod.apply_quorum(&q.sign_policy(&PolicyBundle { target: Role::Prod, key_id: dkg.key_id, version: 1, rules: policy_rules("10000000000000000000") }), now).unwrap();
        say(n, "\n━━ SP7 · Policy: two independent sources, two policy quorums ━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        say(n, format!("  PolicyBundle{{target PROD}} signed by PROD's policy quorum: max/tx 10 ETH, allowlist [{DEST}]"));
        say(n, format!("  PolicyBundle{{target COLD}} signed by COLD's policy quorum: max/tx {} wei", o.cold_max_per_tx));
        if n {
            trace::msg("QUORUM", "PROD", "PolicyBundle", "target PROD · PROD's policy quorum", "quorum");
            trace::msg("QUORUM", "COLD", "PolicyBundle", "target COLD · COLD's policy quorum", "quorum");
        }

        let mut w = World {
            now,
            q,
            hot,
            cold,
            prod,
            rec: None,
            upstream,
            upstream_cert,
            requester,
            requester_cert,
            key_id: dkg.key_id,
            manifest: dkg.manifest.clone(),
            book: dkg.book.clone(),
            dkg: None,
            media: vec![],
            broadcasts: vec![],
            tx_nonce: 0,
            unfreeze_ver: 0,
            revocation_ver: 0,
            last_revocation: None,
            trace: n,
            ev_seen: [0; 3],
            presign_msgs: 0,
            hot_on: false,
            prod_revoked: false,
            prod_gen: 1,
        };
        w.cold.clear_hot_queue(); // HOT received these objects in the ceremony
        w.cold.events.clear();
        w.hot.events.clear();
        w.prod.events.clear();
        w.dkg = Some(dkg);
        say(n, "\n━━ SP1 · Link: COLD dials PROD (nobody dials COLD) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        w.connect_prod();
        w
    }

    pub fn pool(&self, path: &str) -> PoolId {
        PoolId { key_id: self.key_id, key_version: 1, path: path.into() }
    }

    // ------------------------------------------------------------------ transport -------

    /// COLD dials PROD (linked route).
    pub fn connect_prod(&mut self) {
        let tls = B32(rand::random());
        let (nonce, h) = self.cold.dial(tls);
        say(self.trace, "  COLD → PROD   LinkHello (cert, nonce, tls_binding)          PROD: cert ✔ role Cold ✔ binding ✔");
        trace::msg("COLD", "PROD", "LinkHello", "cert · nonce · tls_binding", "hello");
        let reply = self.prod.on_hello(&h, tls, self.now).expect("prod accepts COLD");
        say(self.trace, "  PROD → COLD   LinkHello (peer_nonce echoes COLD's)          COLD: cert ✔ role Prod ✔ nonce ✔");
        trace::msg("PROD", "COLD", "LinkHello", "peer_nonce echoed", "hello");
        self.cold.on_hello_reply(&reply, tls, nonce, self.now).expect("cold accepts PROD");
        self.prod.resend_outbox();
    }

    /// COLD dials HOT (inside a wake window).
    pub fn connect_hot(&mut self) {
        let tls = B32(rand::random());
        let (nonce, h) = self.cold.dial(tls);
        say(self.trace, "  COLD → HOT    LinkHello                                      HOT (booted locked): accepts only COLD");
        trace::msg("COLD", "HOT", "LinkHello", "HOT booted locked: accepts only COLD", "hello");
        let reply = self.hot.on_hello(&h, tls, self.now).expect("hot accepts COLD");
        say(self.trace, "  HOT  → COLD   LinkHello                                      link installed, streams reset");
        trace::msg("HOT", "COLD", "LinkHello", "link installed", "hello");
        self.cold.on_hello_reply(&reply, tls, nonce, self.now).expect("cold accepts HOT");
    }

    /// Move every pending output between parties until the system is quiet.
    pub async fn pump(&mut self) {
        let mut idle = 0;
        for _ in 0..200_000 {
            self.hot.poll(self.now).await;
            self.cold.poll(self.now).await;
            self.prod.poll(self.now);
            let mut moved = false;
            for o in std::mem::take(&mut self.cold.out) {
                moved = true;
                match o {
                    Out::Send { to: Role::Hot, bytes } => {
                        self.trace_frame("COLD", "HOT ", &bytes);
                        self.hot.on_frame(&bytes, self.now)
                    }
                    Out::Send { to: Role::Prod, bytes } => {
                        self.trace_frame("COLD", "PROD", &bytes);
                        self.prod.on_frame(&bytes, self.now)
                    }
                    Out::Display(d) => {
                        say(self.trace, format!("  [COLD display] {d}"));
                        trace::event("COLD", d, "display");
                    }
                    _ => {}
                }
            }
            for o in std::mem::take(&mut self.hot.out) {
                moved = true;
                match o {
                    Out::Send { to: Role::Cold, bytes } => {
                        self.trace_frame("HOT ", "COLD", &bytes);
                        self.cold.on_frame(Role::Hot, &bytes, self.now)
                    }
                    Out::Media(b) => {
                        say(self.trace, format!("  HOT  → 💾     MediaBundle ({} bytes, HPKE ciphertext only PROD can open); HOT erased its halves", b.len()));
                        trace::msg("HOT", "MEDIA", "MediaBundle", format!("{} bytes, sealed to PROD", b.len()), "media");
                        self.media.push(b)
                    }
                    Out::Display(d) => {
                        say(self.trace, format!("  [HOT display]  {d}"));
                        trace::event("HOT", d, "display");
                    }
                    _ => {}
                }
            }
            for o in std::mem::take(&mut self.prod.out) {
                moved = true;
                match o {
                    Out::Send { to: Role::Cold, bytes } => {
                        self.trace_frame("PROD", "COLD", &bytes);
                        self.cold.on_frame(Role::Prod, &bytes, self.now)
                    }
                    Out::Broadcast { chain, signed_tx, txid } => {
                        say(self.trace, format!("  PROD → ⛓     broadcast signed tx {} on {chain}", short(&txid)));
                        trace::msg("PROD", "CHAIN", "broadcast", format!("txid {}", short(&txid)), "chain");
                        self.broadcasts.push((chain, signed_tx, txid))
                    }
                    _ => {}
                }
            }
            self.flush_events();
            if moved {
                idle = 0;
                continue;
            }
            if self.hot.busy() || self.cold.busy() {
                tokio::time::sleep(std::time::Duration::from_micros(200)).await;
                continue;
            }
            idle += 1;
            if idle > 2 {
                self.flush_presign_count();
                self.flush_events();
                self.snap();
                return;
            }
        }
        panic!("pump did not settle");
    }

    fn trace_frame(&mut self, from: &str, to: &str, bytes: &[u8]) {
        if !self.trace {
            return;
        }
        let d = describe(bytes);
        if d.starts_with("PresignMsg") {
            self.presign_msgs += 1;
            return;
        }
        self.flush_presign_count();
        println!("  {from} → {to}   {d}");
        let (label, detail) = d.split_once(" (").map(|(a, b)| (a.trim().to_string(), b.trim_end_matches(')').to_string())).unwrap_or((d.clone(), String::new()));
        let cls = frame_class(&label, &detail);
        trace::msg(from, to, label, detail, cls);
    }

    /// Record the parties' visible state (web demo).
    pub fn snap(&self) {
        if !self.trace {
            return;
        }
        let fz = |k: &chp_core::keyring::Keyring| k.get(&self.key_id, 1).is_some_and(|e| e.frozen.is_some());
        let pool = self.pool(PATH);
        trace::push(trace::Item::State(trace::State {
            hot_on: self.hot_on,
            hot_counter: self.hot.wake_counter(),
            frozen_hot: fz(&self.hot.keyring),
            frozen_cold: fz(&self.cold.st.keyring),
            frozen_prod: fz(&self.prod.keyring),
            prod_pool: self.prod.available(&pool),
            cold_pool: self.cold.pool(&pool).map(|p| p.active_ids().len()).unwrap_or(0),
            broadcasts: self.broadcasts.len(),
            prod_revoked: self.prod_revoked,
            prod_gen: self.prod_gen,
            media: self.media.len(),
        }));
    }

    /// Operator powers HOT on (boots locked).
    pub fn hot_boot(&mut self) {
        self.hot.boot();
        self.hot_on = true;
        self.snap();
    }

    /// HOT powers off (erases session state).
    pub fn hot_off(&mut self) {
        self.hot.power_off();
        self.hot_on = false;
        self.snap();
    }

    fn flush_presign_count(&mut self) {
        if self.presign_msgs > 0 {
            println!("  COLD ⇄ HOT    … {} × PresignMsg (DKLs23 rounds R1–R3, each signed + sequence-checked)", self.presign_msgs);
            trace::msg("COLD", "HOT", format!("PresignMsg ×{}", self.presign_msgs), "DKLs23 R1–R3 both ways, each frame signed + seq-checked", "presign");
            self.presign_msgs = 0;
        }
    }

    /// Print engine events not printed yet.
    pub fn flush_events(&mut self) {
        if !self.trace {
            return;
        }
        for (i, (who, evs)) in [("HOT", &self.hot.events), ("COLD", &self.cold.events), ("PROD", &self.prod.events)].into_iter().enumerate() {
            if evs.len() < self.ev_seen[i] {
                self.ev_seen[i] = 0;
            }
            for e in &evs[self.ev_seen[i]..] {
                println!("{}", describe_event(who, e));
            }
            self.ev_seen[i] = evs.len();
        }
    }

    // ------------------------------------------------------------------ exit / join -----

    /// PROD exits (DESIGN SP1 §8, SP8 §3): the quorum revokes its certificate. Every pool is
    /// discarded (every pool involves PROD's side); no key ceremony is needed (PROD holds no
    /// share). The revocation is queued for HOT's next window.
    pub fn revoke_prod(&mut self) -> Vec<u8> {
        self.revocation_ver += 1;
        let h = B32(chp_crypto::ident::key_hash(&self.prod.enclave.id.public()));
        let rl = self.q.sign(MsgType::RevocationList, &RevocationList { version: self.revocation_ver, revoked: vec![h] });
        self.cold.apply_quorum(&rl, self.now).expect("COLD applies revocation");
        self.last_revocation = Some(rl.clone());
        trace::msg("QUORUM", "COLD", "RevocationList", "v1: SHA-256(PROD id_pk)", "quorum");
        self.prod_revoked = true;
        self.flush_events();
        self.snap();
        rl
    }

    /// A new PROD joins (DESIGN SP8 §3): enroll a fresh enclave, give it public data only,
    /// deliver its certificate to COLD (queued for HOT, which seals bundles to it), link.
    pub fn join_new_prod(&mut self) {
        let ttl = 90 * 86_400;
        let pe = Enclave::new(measurement_of("prod-1.0"));
        let cert = self.q.enroll(&pe.attest_keys(Role::Prod, 0), Role::Prod, 0, 0, pe.id.public(), pe.wrap.public(), self.now, ttl).expect("enroll");
        let mut prod = Prod::new(pe, &self.q.pinned(), 0);
        prod.set_cert(cert.clone());
        let activate = self.q.sign(MsgType::Activate, &KeyControl { key_id: self.key_id, key_version: 1, version: 1 });
        for f in [&self.manifest, &activate, &self.book, &self.upstream_cert, &self.requester_cert] {
            prod.apply_quorum(f, self.now).expect("new PROD public data");
        }
        if let Some(rl) = &self.last_revocation {
            prod.apply_quorum(rl, self.now).expect("new PROD learns the current revocation list");
        }
        prod.apply_quorum(&self.q.sign_policy(&PolicyBundle { target: Role::Prod, key_id: self.key_id, version: 1, rules: policy_rules("10000000000000000000") }), self.now).unwrap();
        self.cold.apply_quorum(&cert, self.now).expect("COLD queues new PROD cert for HOT");
        trace::msg("PROD", "QUORUM", "attestation", "new PROD enclave: measurement + key binding", "quorum");
        trace::msg("QUORUM", "PROD", "PartyCert + manifest + book + Activate + policy", "public data only", "quorum");
        trace::msg("QUORUM", "COLD", "PartyCert (new PROD)", "queued for HOT's next window", "quorum");
        self.prod = prod;
        self.prod_revoked = false;
        self.prod_gen += 1;
        self.ev_seen[2] = 0;
        self.snap();
        self.connect_prod();
    }

    // ------------------------------------------------------------------ operations ------

    /// Open a HOT wake window (two operators), presign `batches` batches for `path`, close it,
    /// and power HOT off. Media bundles are left in `self.media`.
    pub async fn presign_window(&mut self, path: &str, batches: u32) -> Vec<B32> {
        self.hot_boot();
        let counter = self.hot.wake_counter();
        self.connect_hot();
        let digest = self.cold.open_wake(self.key_id, 1, ReturnStage::PresignSync, batches, self.now + 600, counter);
        self.pump().await;
        self.hot.operator_confirm_wake(digest).expect("HOT operator confirms");
        self.pump().await;
        self.cold.operator_confirm_wake().expect("COLD operator confirms");
        self.pump().await;
        let mut ids = vec![];
        for _ in 0..batches {
            ids.push(self.cold.start_batch(path, self.now).expect("start batch"));
            self.pump().await;
        }
        self.cold.close_wake("done");
        self.pump().await;
        self.hot_off();
        self.cold.link_lost(Role::Hot);
        ids
    }

    /// Carry every media bundle to PROD and import it.
    pub async fn carry_media(&mut self) {
        for b in std::mem::take(&mut self.media) {
            let _ = self.prod.import_media(&b, self.now);
            self.pump().await;
        }
    }

    /// Presign and deliver: a full refill.
    pub async fn refill(&mut self, path: &str, batches: u32) -> Vec<B32> {
        let ids = self.presign_window(path, batches).await;
        self.carry_media().await;
        ids
    }

    /// Build an unsigned EIP-1559 withdrawal.
    pub fn tx(&mut self, to: &str, value: u128) -> Vec<u8> {
        let to: [u8; 20] = hex::decode(to.trim_start_matches("0x")).unwrap().try_into().unwrap();
        self.tx_nonce += 1;
        Eip1559 { chain_id: 31337, nonce: self.tx_nonce, max_priority_fee: 1_000_000_000, max_fee: 30_000_000_000, gas_limit: 21_000, to, value, data: vec![] }.encode_unsigned()
    }

    /// UPSTREAM signs a withdrawal envelope.
    pub fn envelope(&self, raw_tx: Vec<u8>, path: &str) -> (B32, Vec<u8>) {
        let request_id = B32(rand::random());
        let env = WithdrawalEnvelope {
            request_id,
            key_id: self.key_id,
            chain: CHAIN.into(),
            raw_tx: Bytes(raw_tx),
            inputs: 1,
            path: path.into(),
            prod_policy_ver: self.prod.policy_version(&self.key_id),
            cold_policy_ver: self.cold.policy_version(&self.key_id),
            not_after: self.now + 120,
            upstream_time: self.now,
        };
        (request_id, sign_body(&self.upstream, MsgType::WithdrawalEnvelope, 0, &env))
    }

    /// Submit a withdrawal to PROD and pump until COLD answers.
    pub async fn withdraw(&mut self, to: &str, value: u128, path: &str) -> Result<u64, chp_engine_prod::Refusal> {
        let raw = self.tx(to, value);
        let (_, env) = self.envelope(raw, path);
        let r = self.prod.withdraw(&env, self.now);
        self.pump().await;
        r
    }

    /// Last Status outcome COLD recorded for a job (from COLD's sealed job table).
    pub fn status_of(&self, job_seq: u64) -> Option<Status> {
        self.cold.job_status(job_seq).map(|s| decode_canonical(&s).unwrap())
    }

    /// Quorum `Unfreeze` to COLD and PROD (and queued for HOT). It names the evidence of the
    /// freeze in force at COLD (the same evidence travelled in the FreezeNotice).
    pub fn unfreeze(&mut self) -> Vec<u8> {
        self.unfreeze_ver += 1;
        let evidence_hash = self.cold.st.keyring.get(&self.key_id, 1).and_then(|e| e.freeze_evidence).unwrap_or_default();
        let u = self.q.ceremony.sign(self.q.m, MsgType::Unfreeze, &UnfreezeBody { key_id: self.key_id, key_version: 1, version: self.unfreeze_ver, evidence_hash });
        self.cold.apply_quorum(&u, self.now).unwrap();
        self.prod.apply_quorum(&u, self.now).unwrap();
        u
    }

    pub fn advance(&mut self, secs: u64) {
        self.now += secs;
    }
}

/// Decode a broadcast EIP-1559 signed tx and recover the sender address.
pub fn recover_sender(signed: &[u8]) -> String {
    use chp_chain::rlp::{self, Item};
    let Item::List(f) = rlp::decode(&signed[1..]).unwrap() else { panic!() };
    let unsigned = Item::List(f[..9].to_vec());
    let mut pre = vec![0x02];
    pre.extend(rlp::encode(&unsigned));
    let h = chp_crypto::hash::keccak256(&pre);
    let y = rlp::as_uint(&f[9]).unwrap() as u8;
    let pad = |b: &[u8]| {
        let mut v = vec![0u8; 32 - b.len()];
        v.extend_from_slice(b);
        v
    };
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&pad(rlp::as_bytes(&f[10]).unwrap()));
    sig[32..].copy_from_slice(&pad(rlp::as_bytes(&f[11]).unwrap()));
    let pk = chp_crypto::verify::ecdsa_recover(&h, &sig, y).unwrap();
    format!("0x{}", hex::encode(chp_chain::evm::address_of(&pk)))
}
