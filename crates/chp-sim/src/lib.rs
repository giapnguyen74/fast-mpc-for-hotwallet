//! In-process simulator of a full CHP deployment (PLAN phase 1 `chp-sim`).
//!
//! [`World`] holds every party (HOT, COLD, PROD engines; REC's HSM; the quorums; UPSTREAM and a
//! requester), a simulated clock, the removable media in transit and a broadcast log standing in
//! for the chain. It moves bytes between engines exactly as the deployment would: links for
//! COLD→HOT and COLD→PROD, media for HOT→PROD, API calls into PROD.

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
}

pub struct Options {
    pub mode: Mode,
    pub batch_size: u16,
    pub paths: Vec<&'static str>,
    /// COLD's limit per tx (PROD's is 10 ETH); lets tests make the two policies differ.
    pub cold_max_per_tx: String,
}

impl Default for Options {
    fn default() -> Self {
        Options { mode: Mode::Standard, batch_size: 4, paths: vec![PATH, PATH2], cold_max_per_tx: "10000000000000000000".into() }
    }
}

pub fn policy_rules(max_per_tx: &str) -> PolicyRules {
    PolicyRules {
        max_per_tx: max_per_tx.into(),
        max_per_day: "100000000000000000000".into(),
        allowlist: vec![DEST.into()],
        chain_ids: vec![31337],
        allow_calldata: false,
    }
}

impl World {
    /// Enroll every party, run the DKG ceremony, deliver shares (SP3), activate, install
    /// policies and certificates, and link COLD → PROD.
    pub async fn setup(o: Options) -> World {
        let now = T0;
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
        hot.ceremony_boot(&dkg.open, now).expect("hot ceremony boot");
        cold.ceremony_boot(&dkg.open, now).expect("cold ceremony boot");
        let hr = hot.import_share(&dkg.manifest, &dkg.hot_package).expect("hot import");
        let cr = cold.import_share(&dkg.manifest, &dkg.cold_package).expect("cold import");
        let mh = chp_core::digest::hash_of(&dkg.manifest);
        check_receipt(&hr, &hc, &mh).expect("hot receipt");
        check_receipt(&cr, &cc, &mh).expect("cold receipt");
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
        };
        w.cold.events.clear();
        w.dkg = Some(dkg);
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
        let reply = self.prod.on_hello(&h, tls, self.now).expect("prod accepts COLD");
        self.cold.on_hello_reply(&reply, tls, nonce, self.now).expect("cold accepts PROD");
        self.prod.resend_outbox();
    }

    /// COLD dials HOT (inside a wake window).
    pub fn connect_hot(&mut self) {
        let tls = B32(rand::random());
        let (nonce, h) = self.cold.dial(tls);
        let reply = self.hot.on_hello(&h, tls, self.now).expect("hot accepts COLD");
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
                    Out::Send { to: Role::Hot, bytes } => self.hot.on_frame(&bytes, self.now),
                    Out::Send { to: Role::Prod, bytes } => self.prod.on_frame(&bytes, self.now),
                    _ => {}
                }
            }
            for o in std::mem::take(&mut self.hot.out) {
                moved = true;
                match o {
                    Out::Send { to: Role::Cold, bytes } => self.cold.on_frame(Role::Hot, &bytes, self.now),
                    Out::Media(b) => self.media.push(b),
                    _ => {}
                }
            }
            for o in std::mem::take(&mut self.prod.out) {
                moved = true;
                match o {
                    Out::Send { to: Role::Cold, bytes } => self.cold.on_frame(Role::Prod, &bytes, self.now),
                    Out::Broadcast { chain, signed_tx, txid } => self.broadcasts.push((chain, signed_tx, txid)),
                    _ => {}
                }
            }
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
                return;
            }
        }
        panic!("pump did not settle");
    }

    // ------------------------------------------------------------------ operations ------

    /// Open a HOT wake window (two operators), presign `batches` batches for `path`, close it,
    /// and power HOT off. Media bundles are left in `self.media`.
    pub async fn presign_window(&mut self, path: &str, batches: u32) -> Vec<B32> {
        self.hot.boot();
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
        self.hot.power_off();
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
            prod_policy_ver: self.prod.policy.version,
            cold_policy_ver: self.cold.policy.version,
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
        self.cold.st.jobs.get(&job_seq).map(|(_, s)| decode_canonical(s).unwrap())
    }

    /// Quorum `Unfreeze` to COLD and PROD (and queued for HOT).
    pub fn unfreeze(&mut self) -> Vec<u8> {
        self.unfreeze_ver += 1;
        let u = self.q.ceremony.sign(self.q.m, MsgType::Unfreeze, &KeyControl { key_id: self.key_id, key_version: 1, version: self.unfreeze_ver });
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
