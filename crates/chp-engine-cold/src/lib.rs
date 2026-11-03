//! COLD engine (DESIGN SP4–SP7, §6.1 COLD hardening).
//!
//! COLD is the only party that can produce a signature. It dials HOT and PROD (nobody dials
//! COLD), drives presign inside agreed wake windows, activates batches only when three
//! independent digests match, and for every job burns first, then re-verifies everything
//! itself: the UPSTREAM signature, its own decode, recomputed ssids, its own policy and ledger,
//! and finally the signature with an independent verifier. Moves towards safety (abort,
//! discard, freeze) are COLD's alone.

pub mod pool;

use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

use chp_auth::{
    link::{accept_hello, check_standalone, make_hello, signer_of, HelloParams, Link},
    sign_body,
    trust::{Pinned, Trust},
};
use chp_core::{
    address::BookView,
    digest::{aad_of, batch_digest, evidence, hash_of, ssid, wake_digest},
    keyring::Keyring,
    replay::ReplayCache,
    Event, Out,
};
use chp_crypto::{
    derive::{derived_key, t_path},
    ecdsa::{cold_complete, EcdsaFragment},
};
use chp_mpc::{presign::BatchRun, share_from_bytes, Keyshare};
use chp_policy::{PolicyState, Verdict};
use chp_tee::Enclave;
use chp_wire::{
    decode_canonical, encode,
    msgs::*,
    presig_id, Bytes, Fault, KeyId, MsgType, PoolId, PresigId, Protocol, QuorumSignedMsg, Role, SignedMsg, B32,
};
use pool::{IdClass, Pool};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct ColdConfig {
    pub replica: u8,
    pub hot_replica: u8,
    pub batch_size: u16,
    /// Seconds PROD has to import a batch after `PresignOpen` (`import_deadline`).
    pub import_window: u64,
    /// Max request validity window (DESIGN SP6 step 2: at most 300 s).
    pub max_request_window: u64,
    /// Max disagreement between the two signed time sources (DESIGN §9.3).
    pub max_time_skew: u64,
}

impl Default for ColdConfig {
    fn default() -> Self {
        ColdConfig { replica: 0, hot_replica: 0, batch_size: 4, import_window: 3600, max_request_window: 300, max_time_skew: 120 }
    }
}

const CEREMONY_COUNTER: &str = "ceremony";

/// Batch states at COLD (DESIGN SP5 §4): `Rounds → Exported → Imported → Active`, or `Aborted`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatchSt {
    Opened,
    Rounds,
    Exported,
    Imported,
    Active,
    Aborted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Batch {
    pub pool: PoolId,
    pub ids: Vec<PresigId>,
    pub st: BatchSt,
    pub own: Option<B32>,
    pub hot: Option<B32>,
    pub prod: Option<B32>,
    pub import_deadline: u64,
}

/// COLD's sealed, restorable state (what a storage snapshot contains).
#[derive(Serialize, Deserialize, Default)]
pub struct Sealed {
    pub pools: BTreeMap<PoolId, Pool>,
    pub batches: BTreeMap<B32, Batch>,
    /// job_seq → (SHA-256 of the job frame body, encoded Status).
    pub jobs: BTreeMap<u64, (B32, Vec<u8>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Wake {
    Closed,
    Proposed { w: WakeOpen, digest: B32, hot_accepted: bool },
    Open { w: WakeOpen, batches: u32 },
}

pub struct Cold {
    pub cfg: ColdConfig,
    pub enclave: Enclave,
    pub trust: Trust,
    cert: Vec<u8>,
    pub keyring: Keyring,
    pub book: BookView,
    pub policy: PolicyState,
    replay: ReplayCache,
    shares: BTreeMap<(KeyId, u32), Arc<Keyshare>>,
    upstream: BTreeMap<B32, PartyCert>,
    pub st: Sealed,
    hot: Option<Link>,
    prod: Option<Link>,
    wake: Wake,
    runs: BTreeMap<B32, BatchRun>,
    /// Quorum files waiting for HOT's next window (RosterUpdate first).
    hot_files: VecDeque<Vec<u8>>,
    /// `OrphanDelete`s to send once PROD is linked (after boot).
    prod_pending: Vec<OrphanDelete>,
    local_time_floor: u64,
    ceremony: Option<CeremonyOpen>,
    pub out: Vec<Out>,
    pub events: Vec<Event>,
}

#[derive(Debug, thiserror::Error)]
pub enum ColdError {
    #[error("refused: {0}")]
    Refused(String),
}

fn refuse<T>(s: impl Into<String>) -> Result<T, ColdError> {
    Err(ColdError::Refused(s.into()))
}

impl Cold {
    pub fn new(cfg: ColdConfig, enclave: Enclave, pinned: &Pinned) -> Self {
        Cold {
            cfg,
            enclave,
            trust: Trust::new(pinned),
            cert: Vec::new(),
            keyring: Keyring::default(),
            book: BookView::default(),
            policy: PolicyState::default(),
            replay: ReplayCache::default(),
            shares: BTreeMap::new(),
            upstream: BTreeMap::new(),
            st: Sealed::default(),
            hot: None,
            prod: None,
            wake: Wake::Closed,
            runs: BTreeMap::new(),
            hot_files: VecDeque::new(),
            prod_pending: Vec::new(),
            local_time_floor: 0,
            ceremony: None,
            out: Vec::new(),
            events: Vec::new(),
        }
    }

    pub fn set_cert(&mut self, c: Vec<u8>) {
        self.cert = c;
    }
    pub fn cert(&self) -> &[u8] {
        &self.cert
    }
    /// Presign runs in progress?
    pub fn busy(&self) -> bool {
        !self.runs.is_empty()
    }
    pub fn hw(&self, p: &PoolId) -> u64 {
        self.enclave.counters.read(&Pool::counter_name(p))
    }
    pub fn batch(&self, b: &B32) -> Option<&Batch> {
        self.st.batches.get(b)
    }
    pub fn pool(&self, p: &PoolId) -> Option<&Pool> {
        self.st.pools.get(p)
    }

    fn ev(&mut self, e: Event) {
        self.events.push(e);
    }
    fn refused(&mut self, what: &str, why: impl Into<String>) {
        self.ev(Event::Refused { what: what.into(), why: why.into() });
    }

    // ------------------------------------------------------------------ storage ---------

    /// Snapshot of sealed storage (for restore drills in the simulator).
    pub fn snapshot(&self) -> Vec<u8> {
        encode(&self.st)
    }

    /// Put an old storage snapshot back (an attack or a careless restore). Hardware counters
    /// are untouched. Takes effect at the next [`Cold::boot`].
    pub fn restore_storage(&mut self, snap: &[u8]) {
        self.st = ciborium::from_reader(snap).expect("snapshot");
    }

    /// Boot (DESIGN §6.1): for each pool, detect a storage restore (sealed counter value below
    /// the hardware value → discard the pool), then increment the pool's counter, closing its
    /// open block, delete own halves of closed blocks and queue `OrphanDelete` for PROD.
    pub fn boot(&mut self) {
        self.hot = None;
        self.prod = None;
        self.wake = Wake::Closed;
        self.runs.clear();
        let pools: Vec<PoolId> = self.st.pools.keys().cloned().collect();
        for p in pools {
            let name = Pool::counter_name(&p);
            let hw_before = self.enclave.counters.read(&name);
            let new = self.enclave.counters.increment(&name);
            let pool = self.st.pools.get_mut(&p).unwrap();
            if pool.last_set_counter < hw_before {
                pool.discard(new as u32);
                let floor = pool.floor_block.unwrap();
                self.events.push(Event::PoolDiscarded { path: p.path.clone(), reason: "storage restore detected".into() });
                self.prod_pending.push(OrphanDelete { pool: p.clone(), presig_ids: vec![], up_to_block: Some(floor + 1) });
            } else {
                pool.delete_below_block(new as u32);
                self.prod_pending.push(OrphanDelete { pool: p.clone(), presig_ids: vec![], up_to_block: Some(new as u32) });
            }
            let pool = self.st.pools.get_mut(&p).unwrap();
            pool.last_set_counter = new;
            pool.next_block = pool.next_block.max(new as u32 + 1);
        }
        // Batches that were mid-flight die with the restart.
        for b in self.st.batches.values_mut() {
            if !matches!(b.st, BatchSt::Active | BatchSt::Aborted) {
                b.st = BatchSt::Aborted;
            }
        }
    }

    // ------------------------------------------------------------------ links -----------

    /// Start a link: COLD dials. Returns COLD's hello.
    pub fn dial(&mut self, tls: B32) -> (B32, Vec<u8>) {
        let nonce = B32(rand::random());
        let h = make_hello(HelloParams {
            id: &self.enclave.id,
            cert: &self.cert,
            roster_updates: vec![],
            nonce,
            peer_nonce: None,
            keys: self.keyring.all().map(|e| (e.manifest.key_id, e.manifest.key_version)).collect(),
            policy_ver: Some(self.policy.version),
            revocation_ver: self.trust.revocation_ver(),
            tls_binding: tls,
        });
        (nonce, h)
    }

    /// Install a link from the peer's hello reply.
    pub fn on_hello_reply(&mut self, bytes: &[u8], tls: B32, my_nonce: B32, now: u64) -> Result<Role, ColdError> {
        let (link, _) = accept_hello(&mut self.trust, Role::Cold, now, bytes, tls, &[Role::Hot, Role::Prod], Some(my_nonce))
            .map_err(|e| ColdError::Refused(e.to_string()))?;
        let role = link.peer.role;
        match role {
            Role::Hot => self.hot = Some(link),
            Role::Prod => {
                self.prod = Some(link);
                for od in std::mem::take(&mut self.prod_pending) {
                    self.send(Role::Prod, MsgType::OrphanDelete, &od);
                }
            }
            _ => return refuse("unexpected peer"),
        }
        Ok(role)
    }

    pub fn link_lost(&mut self, role: Role) {
        match role {
            Role::Hot => {
                self.hot = None;
                for (b, mut r) in std::mem::take(&mut self.runs) {
                    r.abort();
                    self.abort_batch(&b, AbortReason::LinkLost);
                }
                self.wake = Wake::Closed;
            }
            Role::Prod => self.prod = None,
            _ => {}
        }
    }

    fn send(&mut self, to: Role, t: MsgType, body: &impl Serialize) {
        let id = &self.enclave.id;
        let l = match to {
            Role::Hot => self.hot.as_mut(),
            Role::Prod => self.prod.as_mut(),
            _ => None,
        };
        if let Some(l) = l {
            let b = l.seal(id, t, body);
            self.out.push(Out::Send { to, bytes: b });
        }
    }

    /// Handle one frame from HOT or PROD.
    pub fn on_frame(&mut self, from: Role, bytes: &[u8], now: u64) {
        self.local_time_floor = self.local_time_floor.max(now);
        let link = match from {
            Role::Hot => self.hot.as_mut(),
            Role::Prod => self.prod.as_mut(),
            _ => None,
        };
        let Some(link) = link else { return self.refused("frame", "no link") };
        let (t, body) = match link.check(&self.trust, bytes) {
            Ok(x) => x,
            Err(e) => return self.refused("frame", e.to_string()),
        };
        let r = match t {
            MsgType::WakeAccept => self.on_wake_accept(decode_canonical(&body).unwrap()),
            MsgType::WakeClose => {
                self.wake = Wake::Closed;
                Ok(())
            }
            MsgType::PresignAccept => self.on_presign_accept(decode_canonical(&body).unwrap()),
            MsgType::PresignRefuse => {
                let r: PresignRefuse = decode_canonical(&body).unwrap();
                self.end_batch_nothing_stored(&r.batch_id);
                self.ev(Event::Info(format!("presign refused: {:?}", r.reason)));
                Ok(())
            }
            MsgType::PresignMsg => {
                let m: PresignMsg = decode_canonical(&body).unwrap();
                match self.runs.get_mut(&m.batch_id) {
                    Some(r) => r.deliver(m.presig_id, m.payload.0).map_err(|e| ColdError::Refused(e.to_string())),
                    None => refuse("unknown batch"),
                }
            }
            MsgType::PresignStored => self.on_presign_stored(decode_canonical(&body).unwrap()),
            MsgType::TransferAck => self.on_transfer_ack(decode_canonical(&body).unwrap()),
            MsgType::PresignAbort => {
                let a: PresignAbort = decode_canonical(&body).unwrap();
                self.abort_batch(&a.batch_id, a.reason);
                Ok(())
            }
            MsgType::FreezeNotice => {
                let f: FreezeNotice = decode_canonical(&body).unwrap();
                self.freeze(f.key_id, f.key_version, f.fault, f.evidence_hash, Some(from));
                Ok(())
            }
            MsgType::PoolStatus => self.on_pool_status(decode_canonical(&body).unwrap()),
            MsgType::Job => {
                self.on_job(&body, now);
                Ok(())
            }
            other => refuse(format!("{other:?} not handled by COLD")),
        };
        if let Err(e) = r {
            self.refused(&format!("{t:?}"), e.to_string());
        }
    }

    // ------------------------------------------------------------------ wake window -----

    /// COLD's operator requests a window. `hot_counter` is the value HOT displayed at boot.
    pub fn open_wake(&mut self, key_id: KeyId, key_version: u32, stage: ReturnStage, max_batches: u32, not_after: u64, hot_counter: u64) -> B32 {
        let w = WakeOpen { key_id, key_version, return_stage: stage, max_batches, not_after, wake_seq: hot_counter + 1 };
        let digest = wake_digest(&w);
        self.out.push(Out::Display(format!("COLD wake digest {}", hex::encode(&digest.0[..8]))));
        self.send(Role::Hot, MsgType::WakeOpen, &w);
        self.wake = Wake::Proposed { w, digest, hot_accepted: false };
        digest
    }

    fn on_wake_accept(&mut self, a: WakeAccept) -> Result<(), ColdError> {
        match &mut self.wake {
            Wake::Proposed { digest, hot_accepted, .. } if *digest == a.digest => {
                *hot_accepted = true;
                Ok(())
            }
            _ => {
                self.wake = Wake::Closed;
                refuse("WakeAccept digest mismatch: window never opens")
            }
        }
    }

    /// COLD's operator confirms. The window opens; pending quorum files go to HOT first.
    pub fn operator_confirm_wake(&mut self) -> Result<(), ColdError> {
        let Wake::Proposed { w, hot_accepted: true, .. } = &self.wake else { return refuse("HOT has not accepted") };
        let w = w.clone();
        self.wake = Wake::Open { w, batches: 0 };
        // RosterUpdate first, so later files verify against the current roster.
        let mut files: Vec<Vec<u8>> = self.hot_files.drain(..).collect();
        files.sort_by_key(|f| {
            let q: Option<QuorumSignedMsg> = decode_canonical(f).ok();
            q.map(|q| if q.msg_type == MsgType::RosterUpdate.code() { 0 } else { 1 }).unwrap_or(2)
        });
        for f in files {
            self.send(Role::Hot, MsgType::QuorumFile, &QuorumFile { inner: Bytes(f) });
        }
        Ok(())
    }

    pub fn close_wake(&mut self, reason: &str) {
        self.send(Role::Hot, MsgType::WakeClose, &WakeClose { reason: reason.into() });
        self.wake = Wake::Closed;
    }

    pub fn wake_open(&self) -> bool {
        matches!(self.wake, Wake::Open { .. })
    }

    /// Queue a public quorum file for HOT's next window.
    pub fn queue_for_hot(&mut self, file: Vec<u8>) {
        self.hot_files.push_back(file);
    }

    // ------------------------------------------------------------------ presign ---------

    /// Open a batch for `path` (DESIGN SP4 §4 step 1): ids strictly above the pool's
    /// high-water mark, in a fresh block above the pool's hardware counter.
    pub fn start_batch(&mut self, path: &str, now: u64) -> Result<B32, ColdError> {
        let Wake::Open { w, batches } = &self.wake else { return refuse("no open window") };
        if *batches >= w.max_batches || w.return_stage == ReturnStage::ControlOnly {
            return refuse("window batch cap reached");
        }
        let (key_id, kv) = (w.key_id, w.key_version);
        let k = self.keyring.get(&key_id, kv).ok_or(ColdError::Refused("unknown key".into()))?;
        if !k.usable() || !self.book.path_active(&key_id, path) || !self.shares.contains_key(&(key_id, kv)) {
            return refuse("key not usable or path not active");
        }
        let protocol = k.manifest.protocol;
        let pid = PoolId { key_id, key_version: kv, path: path.into() };
        let hw = self.hw(&pid);
        let pool = self.st.pools.entry(pid.clone()).or_default();
        if pool.last_set_counter == 0 && hw == 0 {
            pool.last_set_counter = 0;
        }
        let block = pool.next_block.max(hw as u32 + 1);
        pool.next_block = block + 1;
        let n = self.cfg.batch_size;
        let ids: Vec<PresigId> = (0..n).map(|i| presig_id::make(self.cfg.hot_replica, self.cfg.replica, block, i)).collect();
        if ids[0] <= pool.high_water {
            return refuse("ids not above high-water");
        }
        let batch_id = B32(rand::random());
        pool.issued.insert(block, (batch_id, n));
        if let Wake::Open { batches, .. } = &mut self.wake {
            *batches += 1;
        }
        let import_deadline = now + self.cfg.import_window;
        self.st.batches.insert(batch_id, Batch { pool: pid.clone(), ids: ids.clone(), st: BatchSt::Opened, own: None, hot: None, prod: None, import_deadline });
        let open = PresignOpen { batch_id, key_id, key_version: kv, protocol, presig_ids: ids, path: path.into(), import_deadline };
        self.send(Role::Hot, MsgType::PresignOpen, &open);
        Ok(batch_id)
    }

    fn on_presign_accept(&mut self, a: PresignAccept) -> Result<(), ColdError> {
        let Some(b) = self.st.batches.get_mut(&a.batch_id) else { return refuse("unknown batch") };
        if b.st != BatchSt::Opened {
            return refuse("batch not waiting for accept");
        }
        b.st = BatchSt::Rounds;
        let share = self.shares[&(b.pool.key_id, b.pool.key_version)].clone();
        let run = BatchRun::start(share, a.batch_id.0, &b.ids);
        self.runs.insert(a.batch_id, run);
        Ok(())
    }

    fn end_batch_nothing_stored(&mut self, batch_id: &B32) {
        if let Some(b) = self.st.batches.get_mut(batch_id) {
            b.st = BatchSt::Aborted;
            let ids = b.ids.clone();
            if let Some(p) = self.st.pools.get_mut(&b.pool) {
                for i in ids {
                    p.halves.remove(&i);
                    p.pending.remove(&i);
                    p.gone.insert(i);
                }
            }
        }
        if let Some(mut r) = self.runs.remove(batch_id) {
            r.abort();
        }
    }

    /// Drive presign runs and deadlines.
    pub async fn poll(&mut self, now: u64) {
        self.local_time_floor = self.local_time_floor.max(now);
        let ids: Vec<B32> = self.runs.keys().copied().collect();
        for b in ids {
            let msgs = self.runs.get_mut(&b).unwrap().drain_outgoing();
            for (id, payload) in msgs {
                self.send(Role::Hot, MsgType::PresignMsg, &PresignMsg { batch_id: b, presig_id: id, payload: Bytes(payload) });
            }
            if self.runs[&b].is_finished() {
                let run = self.runs.remove(&b).unwrap();
                let batch = self.st.batches[&b].clone();
                match run.finish().await {
                    Ok(halves) => {
                        let parts: Vec<(u64, Vec<u8>)> = halves.iter().map(|(id, h)| (*id, h.public_part())).collect();
                        let d = batch_digest(&b, &batch.pool.key_id, batch.pool.key_version, &batch.pool.path, &parts);
                        let pool = self.st.pools.get_mut(&batch.pool).unwrap();
                        for (id, h) in halves {
                            pool.pending.insert(id);
                            pool.halves.insert(id, h);
                        }
                        let bm = self.st.batches.get_mut(&b).unwrap();
                        bm.own = Some(d);
                        if bm.st == BatchSt::Rounds {
                            bm.st = BatchSt::Rounds; // waits for PresignStored
                        }
                        self.try_activate(&b);
                    }
                    Err(e) => {
                        self.ev(Event::Info(format!("presign fault: {e}")));
                        self.end_batch_nothing_stored(&b);
                        self.freeze(batch.pool.key_id, batch.pool.key_version, Fault::Presign, b, None);
                        self.close_wake("presign fault");
                    }
                }
            }
        }
        // import deadlines (DESIGN SP5 §5)
        let late: Vec<B32> = self
            .st
            .batches
            .iter()
            .filter(|(_, b)| !matches!(b.st, BatchSt::Active | BatchSt::Aborted) && now > b.import_deadline)
            .map(|(k, _)| *k)
            .collect();
        for b in late {
            self.abort_batch(&b, AbortReason::DeadlinePassed);
        }
    }

    fn on_presign_stored(&mut self, s: PresignStored) -> Result<(), ColdError> {
        let Some(b) = self.st.batches.get_mut(&s.batch_id) else { return refuse("unknown batch") };
        if b.st == BatchSt::Aborted {
            return refuse("batch aborted");
        }
        b.hot = Some(s.digest);
        if matches!(b.st, BatchSt::Rounds | BatchSt::Opened) {
            b.st = BatchSt::Exported;
        }
        self.try_activate(&s.batch_id);
        Ok(())
    }

    fn on_transfer_ack(&mut self, a: BatchDigest) -> Result<(), ColdError> {
        match self.st.batches.get_mut(&a.batch_id) {
            Some(b) if !matches!(b.st, BatchSt::Active | BatchSt::Aborted) => {
                b.prod = Some(a.digest);
                if b.st == BatchSt::Exported {
                    b.st = BatchSt::Imported;
                }
            }
            _ => {
                // An ack for a batch COLD no longer waits for: tell PROD to abort it.
                self.send(Role::Prod, MsgType::PresignAbort, &PresignAbort { batch_id: a.batch_id, reason: AbortReason::NotWaiting });
                return Ok(());
            }
        }
        self.try_activate(&a.batch_id);
        Ok(())
    }

    /// Activate iff own digest = HOT's export digest = PROD's import digest (DESIGN SP5 §3 step 6).
    fn try_activate(&mut self, batch_id: &B32) {
        let Some(b) = self.st.batches.get(batch_id) else { return };
        let (Some(own), Some(hot), Some(prod)) = (b.own, b.hot, b.prod) else {
            if let (Some(own), Some(hot)) = (b.own, b.hot) {
                if own != hot {
                    self.abort_batch(batch_id, AbortReason::DigestMismatch);
                }
            }
            return;
        };
        if own != hot || own != prod {
            self.abort_batch(batch_id, AbortReason::DigestMismatch);
            return;
        }
        let b = self.st.batches.get_mut(batch_id).unwrap();
        b.st = BatchSt::Active;
        let (pid, ids) = (b.pool.clone(), b.ids.clone());
        let pool = self.st.pools.get_mut(&pid).unwrap();
        for i in ids {
            pool.pending.remove(&i);
        }
        self.ev(Event::BatchState { batch_id: *batch_id, state: "Active".into() });
        self.send(Role::Prod, MsgType::PresignActivate, &BatchDigest { batch_id: *batch_id, digest: own });
    }

    /// Abort a non-active batch: delete own pending halves, tell PROD. Active batches are
    /// never aborted (their halves end only by signing, `OrphanDelete` or discard).
    pub fn abort_batch(&mut self, batch_id: &B32, reason: AbortReason) {
        let Some(b) = self.st.batches.get(batch_id) else { return };
        if matches!(b.st, BatchSt::Active | BatchSt::Aborted) {
            return;
        }
        self.end_batch_nothing_stored(batch_id);
        self.ev(Event::BatchState { batch_id: *batch_id, state: format!("Aborted({reason:?})") });
        if reason != AbortReason::ImportRefused {
            self.send(Role::Prod, MsgType::PresignAbort, &PresignAbort { batch_id: *batch_id, reason });
        }
    }

    // ------------------------------------------------------------------ signing ---------

    fn status(&mut self, job_seq: u64, job_hash: B32, request_id: B32, outcome: Outcome, reason: &str, signed: Option<(Vec<u8>, B32)>) {
        let s = Status {
            job_seq,
            request_id,
            outcome,
            reason: reason.into(),
            txid: signed.as_ref().map(|(_, t)| *t),
            signed_tx: signed.map(|(b, _)| Bytes(b)),
        };
        self.st.jobs.insert(job_seq, (job_hash, encode(&s)));
        self.send(Role::Prod, MsgType::Status, &s);
    }

    /// DESIGN SP6 steps 4–6.
    fn on_job(&mut self, body: &[u8], now: u64) {
        let job: Job = decode_canonical(body).expect("validated");
        let job_hash = hash_of(body);
        // 4.2 job_seq first: a resent identical job gets the stored Status; never signed twice.
        if let Some((h, stored)) = self.st.jobs.get(&job.job_seq).cloned() {
            if h == job_hash {
                let s: Status = decode_canonical(&stored).unwrap();
                self.send(Role::Prod, MsgType::Status, &s);
            } else {
                self.refused("Job", "job_seq reused with different content");
            }
            return;
        }
        // Parse (not yet trust) the envelope to find the pool.
        let env_frame: Option<SignedMsg> = decode_canonical(&job.envelope.0).ok();
        let env: Option<WithdrawalEnvelope> = env_frame.as_ref().and_then(|f| decode_canonical(&f.body.0).ok());
        let Some(env) = env else {
            return self.status(job.job_seq, job_hash, B32::default(), Outcome::Rejected, "unparseable envelope", None);
        };
        let pid = PoolId { key_id: env.key_id, key_version: job.key_version, path: env.path.clone() };

        // 4.3 advance the high-water mark, then take every named half, whatever happens next.
        let mut halves = Vec::new();
        let mut verdict: Option<(Outcome, &'static str)> = None;
        if !job.items.windows(2).all(|w| w[0].presig_id < w[1].presig_id) || job.items.is_empty() {
            verdict = Some((Outcome::Rejected, "ids not increasing"));
        }
        let name = Pool::counter_name(&pid);
        match self.st.pools.contains_key(&pid) {
            false => verdict = verdict.or(Some((Outcome::Fault(Fault::PresigState), "presig id never issued"))),
            true => {
                for it in &job.items {
                    let hw = self.enclave.counters.read(&name);
                    let class = self.st.pools[&pid].classify(it.presig_id, hw);
                    match class {
                        IdClass::Take => {
                            // entering a new block advances the hardware counter (by one each)
                            let b = presig_id::block(it.presig_id) as u64;
                            while self.enclave.counters.read(&name) < b {
                                let v = self.enclave.counters.increment(&name);
                                self.st.pools.get_mut(&pid).unwrap().last_set_counter = v;
                            }
                            let pool = self.st.pools.get_mut(&pid).unwrap();
                            halves.push(pool.take_up_to(it.presig_id));
                        }
                        IdClass::Reject(why) => {
                            // burned on both sides: advance the mark, delete it and lower ids
                            let pool = self.st.pools.get_mut(&pid).unwrap();
                            pool.take_up_to(it.presig_id);
                            if verdict.is_none() {
                                verdict = Some((Outcome::Rejected, why));
                            }
                        }
                        IdClass::Fault(why) => {
                            if !matches!(verdict, Some((Outcome::Fault(_), _))) {
                                verdict = Some((Outcome::Fault(Fault::PresigState), why));
                            }
                        }
                    }
                }
            }
        }
        if let Some((o, why)) = verdict {
            if let Outcome::Fault(f) = o {
                self.freeze(env.key_id, job.key_version, f, evidence(body), None);
            }
            return self.status(job.job_seq, job_hash, env.request_id, o, why, None);
        }

        // 4.4 independent re-verification.
        match self.reverify(&job, &env, now) {
            Err((o, why)) => self.status(job.job_seq, job_hash, env.request_id, o, &why, None),
            Ok((decoded, ms)) => {
                // 5 own policy
                if let Verdict::Reject(why) = self.policy.evaluate(&decoded, now) {
                    return self.status(job.job_seq, job_hash, env.request_id, Outcome::Rejected, &format!("COLD policy: {why}"), None);
                }
                // 6 open fragments, combine, verify (independent verifier)
                let k = self.keyring.get(&env.key_id, job.key_version).unwrap();
                let y = k.group_key();
                let t = t_path(&env.key_id.0, &y, &env.path);
                let yp = derived_key(&env.key_id.0, &y, &env.path);
                let mut without = job.clone();
                without.sealed = chp_wire::msgs::Sealed { enc: Bytes::default(), ct: Bytes::default() };
                let aad = aad_of(b"chp-job-aad-v1", &without);
                let sealed = chp_crypto::seal::Sealed { enc: job.sealed.enc.0.clone(), ct: job.sealed.ct.0.clone() };
                let frags: Option<Vec<EcdsaFragment>> = self
                    .enclave
                    .wrap
                    .open(&sealed, b"chp-job-v1", &aad)
                    .ok()
                    .and_then(|pt| ciborium::from_reader(pt.as_slice()).ok());
                let Some(frags) = frags.filter(|f| f.len() == halves.len()) else {
                    self.freeze(env.key_id, job.key_version, Fault::ProdFragment, evidence(body), None);
                    return self.status(job.job_seq, job_hash, env.request_id, Outcome::Fault(Fault::ProdFragment), "undecryptable fragments", None);
                };
                let mut sigs = Vec::new();
                for ((h, f), m) in halves.into_iter().zip(frags.iter()).zip(ms.iter()) {
                    let Some(h) = h else {
                        return self.status(job.job_seq, job_hash, env.request_id, Outcome::Rejected, "half missing", None);
                    };
                    match cold_complete(h, f, m, &t, &yp) {
                        Ok(s) => sigs.push((s.sig, s.recid)),
                        Err(chp_crypto::CryptoError::InvalidPresign) | Err(chp_crypto::CryptoError::Encoding) => {
                            self.freeze(env.key_id, job.key_version, Fault::ProdFragment, evidence(body), None);
                            return self.status(job.job_seq, job_hash, env.request_id, Outcome::Fault(Fault::ProdFragment), "bad fragment", None);
                        }
                        Err(_) => {
                            self.freeze(env.key_id, job.key_version, Fault::FinalVerify, evidence(body), None);
                            return self.status(job.job_seq, job_hash, env.request_id, Outcome::Fault(Fault::FinalVerify), "final signature does not verify", None);
                        }
                    }
                }
                match chp_chain::assemble(&env.chain, &env.raw_tx.0, &sigs) {
                    Ok((signed, txid)) => {
                        self.policy.record(&decoded, now);
                        self.ev(Event::Signed { request_id: env.request_id, txid: B32(txid) });
                        self.status(job.job_seq, job_hash, env.request_id, Outcome::Signed, "", Some((signed, B32(txid))));
                    }
                    Err(e) => self.status(job.job_seq, job_hash, env.request_id, Outcome::Rejected, &e.to_string(), None),
                }
            }
        }
    }

    /// COLD's own checks, independent of PROD (DESIGN SP6 step 4.4).
    fn reverify(&mut self, job: &Job, env: &WithdrawalEnvelope, now: u64) -> Result<(chp_chain::Decoded, Vec<[u8; 32]>), (Outcome, String)> {
        let rej = |s: &str| Err((Outcome::Rejected, s.to_string()));
        // UPSTREAM signature with COLD's own copy of UPSTREAM's certificate
        let signer = signer_of(&job.envelope.0).map_err(|e| (Outcome::Rejected, e.to_string()))?;
        let Some(ucert) = self.upstream.get(&signer).cloned() else { return rej("unknown UPSTREAM signer") };
        if self.trust.is_revoked(&signer) {
            return rej("UPSTREAM revoked");
        }
        check_standalone(&ucert, Role::Cold, &job.envelope.0, MsgType::WithdrawalEnvelope).map_err(|e| (Outcome::Rejected, format!("UPSTREAM signature: {e}")))?;
        // trusted time: two signed sources that must agree, local clock as a floor (DESIGN §9.3)
        if job.prod_time.abs_diff(env.upstream_time) > self.cfg.max_time_skew {
            return rej("time sources disagree");
        }
        let t_now = now.max(job.prod_time).max(self.local_time_floor);
        if env.not_after < env.upstream_time || env.not_after - env.upstream_time > self.cfg.max_request_window {
            return rej("validity window too long");
        }
        if t_now > env.not_after {
            return Err((Outcome::Expired, "request expired".into()));
        }
        if !self.replay.check_and_insert(env.request_id, env.not_after, t_now) {
            return rej("replayed request_id");
        }
        // key state and versions
        let Some(k) = self.keyring.get(&env.key_id, job.key_version) else { return rej("unknown key version") };
        if !k.usable() {
            return rej("key not active or frozen");
        }
        if self.keyring.current(&env.key_id).map(|c| c.manifest.key_version) != Some(job.key_version) {
            return rej("not the current key version");
        }
        if env.cold_policy_ver != self.policy.version {
            return rej("request written against another COLD policy version");
        }
        if k.manifest.chain != env.chain || k.manifest.protocol != Protocol::Dkls23Secp256k1 {
            return rej("chain / protocol mismatch");
        }
        // own decode of raw_tx
        let decoded = chp_chain::decode(&env.chain, &env.raw_tx.0).map_err(|e| (Outcome::Rejected, format!("COLD decode: {e}")))?;
        if decoded.messages.len() != job.items.len() || env.inputs as usize != job.items.len() {
            return rej("input count mismatch");
        }
        // path: equals the presignature's path, Active in COLD's book
        if !self.book.path_active(&env.key_id, &env.path) {
            return rej("path not an Active entry of COLD's address book");
        }
        let pid = PoolId { key_id: env.key_id, key_version: job.key_version, path: env.path.clone() };
        for it in &job.items {
            let block = presig_id::block(it.presig_id);
            let bid = self.st.pools.get(&pid).and_then(|p| p.issued.get(&block)).map(|(b, _)| *b);
            if bid.and_then(|b| self.st.batches.get(&b)).map(|b| &b.pool) != Some(&pid) {
                return rej("presignature opened for another path");
            }
        }
        // recompute every ssid
        for (it, m) in job.items.iter().zip(decoded.messages.iter()) {
            if ssid(&env.chain, &env.key_id, job.key_version, it.presig_id, m, &env.path) != it.ssid {
                return rej("ssid mismatch: PROD and COLD disagree about what is signed");
            }
        }
        Ok((decoded.clone(), decoded.messages.clone()))
    }

    // ------------------------------------------------------------------ control ---------

    /// Freeze on own evidence or a peer's notice; notify the other parties.
    pub fn freeze(&mut self, key_id: KeyId, kv: u32, fault: Fault, evidence_hash: B32, from: Option<Role>) {
        if self.keyring.freeze(&key_id, kv, fault) {
            self.ev(Event::Frozen { key_id, fault });
            let n = FreezeNotice { key_id, key_version: kv, fault, evidence_hash };
            if from != Some(Role::Prod) {
                self.send(Role::Prod, MsgType::FreezeNotice, &n);
            }
            if from != Some(Role::Hot) && self.wake_open() {
                self.send(Role::Hot, MsgType::FreezeNotice, &n);
            }
        }
    }

    fn on_pool_status(&mut self, s: PoolStatus) -> Result<(), ColdError> {
        let Some(pool) = self.st.pools.get_mut(&s.pool) else { return refuse("unknown pool") };
        let mine: std::collections::BTreeSet<PresigId> = pool.active_ids().into_iter().collect();
        let theirs: std::collections::BTreeSet<PresigId> = s.available.iter().copied().collect();
        let only_prod: Vec<PresigId> = theirs.difference(&mine).copied().collect();
        let only_cold: Vec<PresigId> = mine.difference(&theirs).copied().collect();
        for i in &only_cold {
            pool.halves.remove(i);
            pool.gone.insert(*i);
        }
        if !only_prod.is_empty() || !only_cold.is_empty() {
            self.ev(Event::Info(format!("pool mismatch: {} only at PROD, {} only at COLD", only_prod.len(), only_cold.len())));
        }
        if !only_prod.is_empty() {
            self.send(Role::Prod, MsgType::OrphanDelete, &OrphanDelete { pool: s.pool, presig_ids: only_prod, up_to_block: None });
        }
        Ok(())
    }

    fn discard_pools(&mut self, filter: impl Fn(&PoolId) -> bool, reason: &str) {
        let ids: Vec<PoolId> = self.st.pools.keys().filter(|p| filter(p)).cloned().collect();
        for p in ids {
            let hw = self.hw(&p) as u32;
            self.st.pools.get_mut(&p).unwrap().discard(hw);
            self.ev(Event::PoolDiscarded { path: p.path.clone(), reason: reason.into() });
        }
    }

    /// Apply a public quorum-signed object (DESIGN SP7). Objects HOT also needs are queued
    /// for HOT's next window.
    pub fn apply_quorum(&mut self, bytes: &[u8], now: u64) -> Result<(), ColdError> {
        let q: QuorumSignedMsg = decode_canonical(bytes).map_err(|e| ColdError::Refused(e.to_string()))?;
        let t = MsgType::from_code(q.msg_type).ok_or(ColdError::Refused("unknown type".into()))?;
        let e = |x: String| ColdError::Refused(x);
        let for_hot = matches!(t, MsgType::RosterUpdate | MsgType::Unfreeze | MsgType::RevocationList | MsgType::AddressBook | MsgType::KeyManifest | MsgType::Activate | MsgType::Retire);
        match t {
            MsgType::RosterUpdate => {
                self.trust.apply_roster_update(bytes).map_err(|x| e(x.to_string()))?;
            }
            MsgType::KeyManifest => {
                self.keyring.install_manifest(&self.trust, bytes).map_err(|x| e(x.to_string()))?;
            }
            MsgType::Activate => {
                self.keyring.apply_activate(&mut self.trust, bytes).map_err(|x| e(x.to_string()))?;
            }
            MsgType::Retire => {
                let c = self.keyring.apply_retire(&mut self.trust, bytes).map_err(|x| e(x.to_string()))?;
                self.discard_pools(|p| p.key_id == c.key_id && p.key_version == c.key_version, "key version retired");
            }
            MsgType::Unfreeze => {
                let c = self.keyring.apply_unfreeze(&mut self.trust, bytes).map_err(|x| e(x.to_string()))?;
                self.ev(Event::Unfrozen { key_id: c.key_id });
            }
            MsgType::RevocationList => {
                let newly = self.trust.apply_revocation(bytes).map_err(|x| e(x.to_string()))?;
                let mut share_side = false;
                for h in &newly {
                    for (role, l) in [(Role::Hot, &self.hot), (Role::Prod, &self.prod)] {
                        if l.as_ref().is_some_and(|l| l.peer_signer == *h) {
                            share_side = true;
                            let _ = role;
                        }
                    }
                    if self.upstream.remove(h).is_some() {
                        // revoking UPSTREAM discards no pool
                    }
                    if *h == B32(chp_crypto::ident::key_hash(&self.enclave.id.public())) {
                        share_side = true;
                    }
                }
                if self.hot.as_ref().is_some_and(|l| newly.contains(&l.peer_signer)) {
                    self.link_lost(Role::Hot);
                }
                if self.prod.as_ref().is_some_and(|l| newly.contains(&l.peer_signer)) {
                    self.link_lost(Role::Prod);
                }
                // Revoking HOT, COLD or PROD discards every pool (DESIGN SP1 §8). COLD cannot
                // tell from the hash alone whether an unlinked party was HOT/PROD, so any
                // revocation of a non-client discards conservatively.
                if share_side || newly.iter().any(|h| !self.upstream.contains_key(h)) {
                    self.discard_pools(|_| true, "party revoked");
                }
            }
            MsgType::PolicyBundle => {
                let pb: PolicyBundle = self.trust.verify_quorum(bytes, MsgType::PolicyBundle).map_err(|x| e(x.to_string()))?;
                if pb.target != Role::Cold {
                    return refuse("PolicyBundle addressed to another party");
                }
                self.trust.bump_version("policy", pb.version).map_err(|x| e(x.to_string()))?;
                self.policy.install(pb.version, pb.rules);
            }
            MsgType::AddressBook => {
                let b: AddressBook = self.trust.verify_quorum(bytes, MsgType::AddressBook).map_err(|x| e(x.to_string()))?;
                let k = self.keyring.get(&b.key_id, b.key_version).ok_or(e("unknown key".into()))?;
                let (m, h) = (k.manifest.clone(), k.manifest_hash);
                self.book.install(&self.trust, bytes, &m, &h).map_err(|x| e(x.to_string()))?;
            }
            MsgType::PartyCert => {
                let (c, _) = self.trust.verify_cert(bytes, now).map_err(|x| e(x.to_string()))?;
                match c.role {
                    Role::Upstream => {
                        self.upstream.insert(B32(chp_crypto::ident::key_hash(&c.id_pk.0)), c);
                    }
                    Role::Prod => self.queue_for_hot(bytes.to_vec()),
                    _ => return refuse("COLD stores UPSTREAM and PROD certificates only"),
                }
            }
            MsgType::SharePackage => return refuse("COLD never accepts key material over a runtime path"),
            other => return refuse(format!("{other:?} not accepted")),
        }
        if for_hot {
            self.queue_for_hot(bytes.to_vec());
        }
        Ok(())
    }

    // ------------------------------------------------------------------ ceremony --------

    /// Ceremony boot for COLD: `boot_seq[Cold]` = ceremony counter + 1.
    pub fn ceremony_boot(&mut self, open: &[u8], now: u64) -> Result<CeremonyOpen, ColdError> {
        let o: CeremonyOpen = self.trust.verify_quorum(open, MsgType::CeremonyOpen).map_err(|e| ColdError::Refused(e.to_string()))?;
        let want = self.enclave.counters.read(CEREMONY_COUNTER) + 1;
        if now > o.not_after || !o.boot_seq.contains(&(Role::Cold, want)) {
            return refuse("ceremony expired or boot_seq mismatch");
        }
        self.enclave.counters.increment(CEREMONY_COUNTER);
        self.ceremony = Some(o.clone());
        Ok(o)
    }

    /// SP3 import (ceremony mode only). Returns the signed `ShareReceipt`.
    pub fn import_share(&mut self, manifest: &[u8], package: &[u8]) -> Result<Vec<u8>, ColdError> {
        let Some(open) = &self.ceremony else { return refuse("share packages only in ceremony mode") };
        let e = |x: String| ColdError::Refused(x);
        let entry = self.keyring.install_manifest(&self.trust, manifest).map_err(|x| e(x.to_string()))?.clone();
        let p: SharePackage = self.trust.verify_quorum(package, MsgType::SharePackage).map_err(|x| e(x.to_string()))?;
        let me = chp_mpc::dkls::PARTY_COLD;
        if p.manifest_hash != entry.manifest_hash || p.party_index != me || p.ceremony_id != open.ceremony_id || p.key_id != entry.manifest.key_id {
            return refuse("package does not match manifest / party / ceremony");
        }
        if self.shares.contains_key(&(p.key_id, p.key_version)) {
            return refuse("already imported");
        }
        let mut info = b"chp-share-v1".to_vec();
        info.extend_from_slice(&p.key_id.0);
        info.extend_from_slice(&p.key_version.to_be_bytes());
        info.push(p.party_index);
        info.extend_from_slice(&p.ceremony_id.0);
        let sealed = chp_crypto::seal::Sealed { enc: p.sealed.enc.0.clone(), ct: p.sealed.ct.0.clone() };
        let bytes = self.enclave.wrap.open(&sealed, &info, &[]).map_err(|x| e(x.to_string()))?;
        let share = share_from_bytes(&bytes).ok_or(e("bad share".into()))?;
        let mine = entry.manifest.parties.iter().find(|x| x.role == Role::Cold).ok_or(e("no COLD entry".into()))?;
        if chp_crypto::ecdsa::enc_point(&share.big_s(share.party_id)).to_vec() != mine.public_share.0
            || chp_crypto::ecdsa::enc_point(&share.public_key()).to_vec() != entry.manifest.group_key.0
        {
            return refuse("s_i·G != Y_i");
        }
        self.shares.insert((p.key_id, p.key_version), Arc::new(share));
        let r = ShareReceipt {
            key_id: p.key_id,
            key_version: p.key_version,
            party_index: me,
            public_share: mine.public_share.clone(),
            measurement: self.enclave.measurement,
            manifest_hash: entry.manifest_hash,
        };
        Ok(sign_body(&self.enclave.id, MsgType::ShareReceipt, 0, &r))
    }

    pub fn end_ceremony(&mut self) {
        self.ceremony = None;
    }
}
