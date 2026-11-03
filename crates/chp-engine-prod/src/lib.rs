//! PROD engine (DESIGN SP5 import, SP6 admission + fragment, SP7, SP10 answers).
//!
//! PROD is the only internet-facing party. It holds HOT's presignature halves only, never a
//! key share. At runtime it can: import a media bundle; check a request; send one fragment
//! (`Job`); send `PoolStatus`, `TransferAck`, `PresignAbort`, `FreezeNotice`; answer
//! `AddressQuery`. It accepts only COLD's link and opens none.

use std::collections::BTreeMap;

use chp_auth::{
    link::{accept_hello, check_standalone, make_hello, signer_of, HelloParams, Link},
    sign_body,
    trust::{Pinned, Trust},
};
use chp_core::{
    address::BookView,
    digest::{aad_of, batch_digest, ssid},
    keyring::Keyring,
    replay::ReplayCache,
    Event, Out,
};
use chp_crypto::{
    derive::t_path,
    ecdsa::{prod_fragment, EcdsaFragment, EcdsaHalf},
    seal::seal,
};
use chp_policy::{PolicyState, Verdict};
use chp_tee::Enclave;
use chp_wire::{
    decode_canonical, encode,
    msgs::*,
    presig_id, Bytes, KeyId, MsgType, PoolId, PresigId, QuorumSignedMsg, Role, B32,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PBatch {
    Pending,
    Active,
    Aborted,
}

#[derive(Debug)]
struct BatchRec {
    pool: PoolId,
    ids: Vec<PresigId>,
    st: PBatch,
    import_deadline: u64,
    digest: B32,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Refusal {
    #[error("refused at admission: {0}")]
    Admission(String),
    #[error("bundle refused: {0}")]
    Bundle(String),
    #[error("{0}")]
    Other(String),
}

pub struct Prod {
    pub enclave: Enclave,
    pub trust: Trust,
    cert: Vec<u8>,
    cold_replica: u8,
    pub keyring: Keyring,
    pub book: BookView,
    /// Per-key policy (a bundle for one key never applies to another).
    pub policy: BTreeMap<KeyId, PolicyState>,
    replay: ReplayCache,
    query_replay: ReplayCache,
    clients: BTreeMap<B32, PartyCert>,
    pools: BTreeMap<PoolId, BTreeMap<PresigId, (EcdsaHalf, B32)>>,
    high_water: BTreeMap<PoolId, PresigId>,
    batches: BTreeMap<B32, BatchRec>,
    cold: Option<Link>,
    cold_wrap_pk: Option<B32>,
    /// HOT signers seen on imported bundles (to know whether a revocation hits HOT).
    hot_signers: std::collections::BTreeSet<B32>,
    next_job_seq: u64,
    /// job_seq → encoded Job frame body (re-sent after a reconnect).
    outbox: BTreeMap<u64, Job>,
    pending_env: BTreeMap<u64, (WithdrawalEnvelope, chp_chain::Decoded, u64)>,
    /// Control messages for COLD waiting for the link.
    queued: Vec<(u16, Vec<u8>)>,
    pub out: Vec<Out>,
    pub events: Vec<Event>,
}

impl Prod {
    pub fn new(mut enclave: Enclave, pinned: &Pinned, cold_replica: u8) -> Self {
        // job_seq starts from a hardware boot counter, so a restarted PROD with the same identity
        // never reuses a job_seq COLD has already seen (security review round 2).
        let boot = enclave.counters.increment("prod-boot");
        let first_job_seq = (boot << 32) | 1;
        Prod {
            enclave,
            trust: Trust::new(pinned),
            cert: Vec::new(),
            cold_replica,
            keyring: Keyring::default(),
            book: BookView::default(),
            policy: BTreeMap::new(),
            replay: ReplayCache::default(),
            query_replay: ReplayCache::default(),
            clients: BTreeMap::new(),
            pools: BTreeMap::new(),
            high_water: BTreeMap::new(),
            batches: BTreeMap::new(),
            cold: None,
            cold_wrap_pk: None,
            hot_signers: Default::default(),
            next_job_seq: first_job_seq,
            outbox: BTreeMap::new(),
            pending_env: BTreeMap::new(),
            queued: Vec::new(),
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
    pub fn available(&self, p: &PoolId) -> usize {
        self.pools.get(p).map(|m| m.keys().filter(|id| self.is_active(p, **id)).count()).unwrap_or(0)
    }
    pub fn batch_state(&self, b: &B32) -> Option<PBatch> {
        self.batches.get(b).map(|r| r.st)
    }
    pub fn held_ids(&self, p: &PoolId) -> Vec<PresigId> {
        self.pools.get(p).map(|m| m.keys().copied().collect()).unwrap_or_default()
    }
    /// Policy version in force for a key (0 = none).
    pub fn policy_version(&self, key_id: &KeyId) -> u64 {
        self.policy.get(key_id).map(|p| p.version).unwrap_or(0)
    }
    pub fn outbox_len(&self) -> usize {
        self.outbox.len()
    }

    fn is_active(&self, _p: &PoolId, id: PresigId) -> bool {
        self.pools
            .get(_p)
            .and_then(|m| m.get(&id))
            .and_then(|(_, b)| self.batches.get(b))
            .is_some_and(|b| b.st == PBatch::Active)
    }

    fn refused(&mut self, what: &str, why: impl Into<String>) {
        self.events.push(Event::Refused { what: what.into(), why: why.into() });
    }

    /// Test/attack helper: copy PROD's halves (a breach). Returns (pool, id, half) for every
    /// half held.
    #[cfg(feature = "sim-hooks")]
    pub fn steal_halves(&self) -> Vec<(PoolId, PresigId, EcdsaHalf)> {
        self.pools.iter().flat_map(|(p, m)| m.iter().map(move |(id, (h, _))| (p.clone(), *id, h.duplicate_for_test()))).collect()
    }

    // ------------------------------------------------------------------ adversary hooks -
    // Compiled only with the `sim-hooks` feature (simulator / tests): a production PROD has no
    // API that copies or extracts halves (security review).

    /// **Test hook modelling a compromised PROD**: take a half out of the store (as an attacker
    /// with code execution on PROD could).
    #[cfg(feature = "sim-hooks")]
    pub fn adversary_take_half(&mut self, pool: &PoolId, id: PresigId) -> Option<EcdsaHalf> {
        self.pools.get_mut(pool).and_then(|m| m.remove(&id)).map(|(h, _)| h)
    }

    /// **Test hook modelling a compromised PROD**: send an arbitrary `Job` with arbitrary
    /// fragments, correctly sealed to COLD and signed with PROD's own identity key.
    #[cfg(feature = "sim-hooks")]
    pub fn adversary_send_job(&mut self, mut job: Job, frags: &[EcdsaFragment]) {
        job.sealed = Sealed { enc: Bytes::default(), ct: Bytes::default() };
        let aad = aad_of(b"chp-job-aad-v1", &job);
        let wrap = self.cold_wrap_pk.expect("linked");
        let s = seal(&wrap.0, b"chp-job-v1", &aad, &encode(&frags), &mut rand::thread_rng()).unwrap();
        job.sealed = Sealed { enc: Bytes(s.enc), ct: Bytes(s.ct) };
        self.outbox.insert(job.job_seq, job.clone());
        self.send(MsgType::Job, &job);
    }

    /// **Test hook**: send raw bytes as if they were a sealed job ciphertext (tampering).
    #[cfg(feature = "sim-hooks")]
    pub fn adversary_send_job_raw(&mut self, job: Job) {
        self.send(MsgType::Job, &job);
    }

    /// Next job sequence number PROD will use.
    pub fn next_job_seq(&self) -> u64 {
        self.next_job_seq
    }
    #[cfg(feature = "sim-hooks")]
    pub fn adversary_bump_job_seq(&mut self) -> u64 {
        let s = self.next_job_seq;
        self.next_job_seq += 1;
        s
    }

    // ------------------------------------------------------------------ link ------------

    /// PROD accepts only COLD's link and opens none.
    pub fn on_hello(&mut self, bytes: &[u8], tls: B32, now: u64) -> Result<Vec<u8>, Refusal> {
        let my_nonce = B32(rand::random());
        let (link, h) = accept_hello(&mut self.trust, Role::Prod, now, bytes, tls, &[Role::Cold], None, my_nonce).map_err(|e| Refusal::Other(e.to_string()))?;
        // Only this PROD's COLD replica, on the linked route (security review).
        if link.peer.replica != self.cold_replica || link.peer.qr_route {
            return Err(Refusal::Other("COLD replica or route not paired with this PROD".into()));
        }
        // A new hello replaces the link: everything that a link loss aborts is aborted.
        if self.cold.is_some() {
            self.link_lost();
        }
        self.cold_wrap_pk = Some(link.peer.wrap_pk);
        self.cold = Some(link);
        self.flush_queue();
        let reply = make_hello(HelloParams {
            id: &self.enclave.id,
            cert: &self.cert,
            roster_updates: vec![],
            nonce: my_nonce,
            peer_nonce: Some(h.nonce),
            keys: self.keyring.all().map(|e| (e.manifest.key_id, e.manifest.key_version)).collect(),
            policy_ver: None,
            revocation_ver: self.trust.revocation_ver(),
            tls_binding: tls,
        });
        Ok(reply)
    }

    /// Re-send every job still waiting for a Status (after a reconnect).
    pub fn resend_outbox(&mut self) {
        let jobs: Vec<Job> = self.outbox.values().cloned().collect();
        for j in jobs {
            self.send(MsgType::Job, &j);
        }
    }

    /// Link to COLD lost: every `Pending` batch is aborted (DESIGN SP5 §5).
    pub fn link_lost(&mut self) {
        self.cold = None;
        let pend: Vec<B32> = self.batches.iter().filter(|(_, b)| b.st == PBatch::Pending).map(|(k, _)| *k).collect();
        for b in pend {
            self.abort_local(&b);
        }
    }

    fn send(&mut self, t: MsgType, body: &impl serde::Serialize) {
        if let Some(l) = self.cold.as_mut() {
            let b = l.seal(&self.enclave.id, t, body);
            self.out.push(Out::Send { to: Role::Cold, bytes: b });
        } else if t != MsgType::Job {
            // control messages are not lost while unlinked (jobs are re-sent from the outbox)
            self.queued.push((t.code(), encode(body)));
        }
    }

    fn flush_queue(&mut self) {
        let Some(l) = self.cold.as_mut() else { return };
        for (t, body) in std::mem::take(&mut self.queued) {
            let b = l.seal_raw(&self.enclave.id, MsgType::from_code(t).expect("queued"), body);
            self.out.push(Out::Send { to: Role::Cold, bytes: b });
        }
    }

    // ------------------------------------------------------------------ SP5 import ------

    /// Import a media bundle (DESIGN SP5 §3 step 5).
    pub fn import_media(&mut self, bundle: &[u8], now: u64) -> Result<(), Refusal> {
        let r = |s: String| Refusal::Bundle(s);
        let mb: MediaBundle = decode_canonical(bundle).map_err(|e| r(e.to_string()))?;
        // Authenticate: certificate (roster, role HOT, validity, not revoked), signer, seq 0,
        // signature. Failure here changes nothing.
        let (cert, _) = self.trust.verify_cert(&mb.hot_cert.0, now).map_err(|e| r(e.to_string()))?;
        if cert.role != Role::Hot {
            return Err(r("bundle certificate is not HOT's".into()));
        }
        let (seq, body) = check_standalone(&cert, Role::Prod, &mb.transfer.0, MsgType::PresigTransfer).map_err(|e| r(e.to_string()))?;
        if seq != 0 {
            return Err(r("transfer seq must be 0".into()));
        }
        let tr: PresigTransfer = decode_canonical(&body).map_err(|e| r(e.to_string()))?;
        self.hot_signers.insert(B32(chp_crypto::ident::key_hash(&cert.id_pk.0)));
        // Batch state: replay of a live batch is ignored; an aborted batch is refused.
        match self.batches.get(&tr.batch_id).map(|b| b.st) {
            Some(PBatch::Pending) | Some(PBatch::Active) => return Ok(()),
            Some(PBatch::Aborted) => return Err(r("batch already aborted".into())),
            None => {}
        }
        // Content checks; a refusal of an authenticated bundle aborts the batch.
        match self.import_content(&tr, now, cert.replica) {
            Ok(halves) => {
                let pid = PoolId { key_id: tr.key_id, key_version: tr.key_version, path: tr.path.clone() };
                let pool = self.pools.entry(pid.clone()).or_default();
                for (id, h) in halves {
                    pool.insert(id, (h, tr.batch_id));
                }
                self.batches.insert(tr.batch_id, BatchRec { pool: pid, ids: tr.presig_ids.clone(), st: PBatch::Pending, import_deadline: tr.import_deadline, digest: tr.digest });
                self.send(MsgType::TransferAck, &BatchDigest { batch_id: tr.batch_id, digest: tr.digest });
                Ok(())
            }
            Err(why) => {
                let pid = PoolId { key_id: tr.key_id, key_version: tr.key_version, path: tr.path.clone() };
                self.batches.insert(tr.batch_id, BatchRec { pool: pid, ids: vec![], st: PBatch::Aborted, import_deadline: 0, digest: tr.digest });
                self.send(MsgType::PresignAbort, &PresignAbort { batch_id: tr.batch_id, reason: AbortReason::ImportRefused });
                Err(r(why))
            }
        }
    }

    fn import_content(&self, tr: &PresigTransfer, now: u64, hot_replica: u8) -> Result<Vec<(PresigId, EcdsaHalf)>, String> {
        let k = self.keyring.get(&tr.key_id, tr.key_version).ok_or("unknown key version")?;
        if k.state != chp_wire::KeyState::Active {
            return Err("key not active".into());
        }
        if now > tr.import_deadline {
            return Err("import deadline passed".into());
        }
        if tr.presig_ids.is_empty() || tr.presig_ids.len() > 256 || !tr.presig_ids.windows(2).all(|w| w[0] < w[1]) {
            return Err("ids must be 1..=256 and strictly increasing".into());
        }
        if tr.presig_ids.iter().any(|i| presig_id::replicas(*i) != (hot_replica, self.cold_replica)) {
            return Err("ids outside this replica's range".into());
        }
        let pid = PoolId { key_id: tr.key_id, key_version: tr.key_version, path: tr.path.clone() };
        if self.pools.get(&pid).is_some_and(|m| tr.presig_ids.iter().any(|i| m.contains_key(i))) {
            return Err("ids already held (pending or active)".into());
        }
        if let Some(hw) = self.high_water.get(&pid) {
            if tr.presig_ids.first().is_some_and(|f| f <= hw) {
                return Err("store high-water mark refuses these ids".into());
            }
        }
        let mut without = tr.clone();
        without.sealed = Sealed { enc: Bytes::default(), ct: Bytes::default() };
        let aad = aad_of(b"chp-transfer-aad-v1", &without);
        let sealed = chp_crypto::seal::Sealed { enc: tr.sealed.enc.0.clone(), ct: tr.sealed.ct.0.clone() };
        let pt = self.enclave.wrap.open(&sealed, b"chp-transfer-v1", &aad).map_err(|_| "HPKE open failed")?;
        let halves: Vec<(PresigId, EcdsaHalf)> = ciborium::from_reader(pt.as_slice()).map_err(|_| "bad half list")?;
        let ids: Vec<PresigId> = halves.iter().map(|(i, _)| *i).collect();
        if ids != tr.presig_ids {
            return Err("half ids do not match the transfer".into());
        }
        let parts: Vec<(u64, Vec<u8>)> = halves.iter().map(|(id, h)| (*id, h.public_part())).collect();
        if batch_digest(&tr.batch_id, &tr.key_id, tr.key_version, &tr.path, &parts) != tr.digest {
            return Err("recomputed digest differs".into());
        }
        Ok(halves)
    }

    fn abort_local(&mut self, b: &B32) {
        if let Some(rec) = self.batches.get_mut(b) {
            if rec.st == PBatch::Active {
                return;
            }
            rec.st = PBatch::Aborted;
            if let Some(pool) = self.pools.get_mut(&rec.pool) {
                for i in &rec.ids {
                    pool.remove(i);
                }
            }
        }
    }

    // ------------------------------------------------------------------ frames ----------

    pub fn on_frame(&mut self, bytes: &[u8], now: u64) {
        let Some(link) = self.cold.as_mut() else { return self.refused("frame", "no link") };
        let (t, body) = match link.check(&self.trust, now, bytes) {
            Ok(x) => x,
            Err(e) => return self.refused("frame", e.to_string()),
        };
        match t {
            MsgType::PresignActivate => {
                let a: BatchDigest = decode_canonical(&body).unwrap();
                match self.batches.get_mut(&a.batch_id) {
                    Some(b) if b.st == PBatch::Pending && b.digest == a.digest => {
                        b.st = PBatch::Active;
                        // the high-water mark moves only for batches COLD activated (a forged
                        // HOT bundle can never block the pool; security review round 2)
                        let top = *b.ids.last().unwrap();
                        let hw = self.high_water.entry(b.pool.clone()).or_insert(0);
                        *hw = (*hw).max(top);
                        self.events.push(Event::BatchState { batch_id: a.batch_id, state: "Active".into() });
                    }
                    _ => self.refused("PresignActivate", "batch not pending"),
                }
            }
            MsgType::PresignAbort => {
                let a: PresignAbort = decode_canonical(&body).unwrap();
                match self.batches.get(&a.batch_id) {
                    // aborted before import: record it so a late bundle is refused
                    None => {
                        self.batches.insert(a.batch_id, BatchRec { pool: PoolId { key_id: B32::default(), key_version: 0, path: String::new() }, ids: vec![], st: PBatch::Aborted, import_deadline: 0, digest: B32::default() });
                    }
                    Some(_) => self.abort_local(&a.batch_id),
                }
            }
            MsgType::Status => self.on_status(decode_canonical(&body).unwrap()),
            MsgType::FreezeNotice => {
                let f: FreezeNotice = decode_canonical(&body).unwrap();
                if self.keyring.freeze(&f.key_id, f.key_version, f.fault, f.evidence_hash) {
                    self.events.push(Event::Frozen { key_id: f.key_id, fault: f.fault });
                }
            }
            MsgType::OrphanDelete => {
                let o: OrphanDelete = decode_canonical(&body).unwrap();
                if let Some(pool) = self.pools.get_mut(&o.pool) {
                    pool.retain(|id, _| !o.presig_ids.contains(id) && o.up_to_block.is_none_or(|b| presig_id::block(*id) >= b));
                }
            }
            other => self.refused(&format!("{other:?}"), "not handled by PROD"),
        }
        let _ = now;
    }

    fn on_status(&mut self, s: Status) {
        let Some(job) = self.outbox.remove(&s.job_seq) else { return self.refused("Status", "unknown job") };
        let _ = job;
        if let (Outcome::Signed, Some(tx), Some(txid)) = (s.outcome, s.signed_tx.as_ref(), s.txid) {
            let env = self.pending_env.remove(&s.job_seq);
            if let Some((env, _decoded, _when)) = env {
                self.out.push(Out::Broadcast { chain: env.chain, signed_tx: tx.0.clone(), txid });
            }
        } else {
            if let Some((env, decoded, when)) = self.pending_env.remove(&s.job_seq) {
                if let Some(p) = self.policy.get_mut(&env.key_id) {
                    p.release(&decoded, when); // not signed: give the reservation back
                }
            }
            self.events.push(Event::Info(format!("job {} → {:?}: {}", s.job_seq, s.outcome, s.reason)));
        }
    }

    // ------------------------------------------------------------------ SP6 -------------

    /// SP6 steps 2–3: admission (no state change on refusal), take = delete, fragment, `Job`.
    pub fn withdraw(&mut self, envelope_frame: &[u8], now: u64) -> Result<u64, Refusal> {
        let adm = |s: &str| Refusal::Admission(s.to_string());
        let signer = signer_of(envelope_frame).map_err(|e| adm(&e.to_string()))?;
        let cert = self.clients.get(&signer).cloned().ok_or(adm("unknown signer"))?;
        if now > cert.not_after || now < cert.not_before {
            return Err(adm("UPSTREAM certificate outside its validity window"));
        }
        if cert.role != Role::Upstream {
            return Err(adm("only UPSTREAM may request withdrawals"));
        }
        let (_, body) = check_standalone(&cert, Role::Prod, envelope_frame, MsgType::WithdrawalEnvelope).map_err(|e| adm(&e.to_string()))?;
        let env: WithdrawalEnvelope = decode_canonical(&body).map_err(|e| adm(&e.to_string()))?;
        if !cert.key_ids.is_empty() && !cert.key_ids.contains(&env.key_id) {
            return Err(adm("UPSTREAM certificate does not cover this key"));
        }
        if now > env.not_after || env.not_after.saturating_sub(env.upstream_time) > 300 || env.not_after > now + 300 || env.upstream_time > now + 120 {
            return Err(adm("expired or validity window over 300 s"));
        }
        if self.replay.contains(&env.request_id) {
            return Err(adm("request_id seen before"));
        }
        let k = self.keyring.current(&env.key_id).ok_or(adm("unknown key"))?;
        if !k.usable() {
            return Err(adm("key not active or frozen"));
        }
        let kv = k.manifest.key_version;
        if k.manifest.chain != env.chain || env.prod_policy_ver != self.policy_version(&env.key_id) {
            return Err(adm("chain or PROD policy version mismatch"));
        }
        let decoded = chp_chain::decode(&env.chain, &env.raw_tx.0).map_err(|e| adm(&format!("PROD decode: {e}")))?;
        if decoded.messages.len() != env.inputs as usize {
            return Err(adm("input count"));
        }
        if !self.book.path_active(&env.key_id, &env.path) {
            return Err(adm("path not in address book"));
        }
        let verdict = self.policy.get(&env.key_id).map(|p| p.evaluate(&decoded, now)).unwrap_or(Verdict::Reject("no policy for this key".into()));
        if let Verdict::Reject(why) = verdict {
            return Err(adm(&format!("PROD policy: {why}")));
        }
        let pid = PoolId { key_id: env.key_id, key_version: kv, path: env.path.clone() };
        let active: Vec<PresigId> = self.pools.get(&pid).map(|m| m.keys().copied().filter(|i| self.is_active(&pid, *i)).collect()).unwrap_or_default();
        if active.len() < decoded.messages.len() {
            return Err(adm("not enough active presignatures"));
        }
        let wrap = self.cold_wrap_pk.ok_or(adm("no COLD link"))?;
        // ---- admission passed: from here state changes ----
        self.replay.check_and_insert(env.request_id, env.not_after, now);
        // Reserve the amount now; released if COLD does not sign (security review round 2: a
        // burst of requests admitted before any Status came back bypassed the daily limit).
        if let Some(p) = self.policy.get_mut(&env.key_id) {
            p.record(&decoded, now);
        }
        let y = k.group_key();
        let t = t_path(&env.key_id.0, &y, &env.path);
        let mut items = Vec::new();
        let mut frags: Vec<EcdsaFragment> = Vec::new();
        for (i, m) in decoded.messages.iter().enumerate() {
            // take the next half in strictly increasing id order: deleted before computing
            let id = active[i];
            let (half, _) = self.pools.get_mut(&pid).unwrap().remove(&id).unwrap();
            items.push(JobItem { input: i as u32, presig_id: id, ssid: ssid(&env.chain, &env.key_id, kv, id, m, &env.path) });
            frags.push(prod_fragment(half, m, &t).map_err(|e| Refusal::Other(e.to_string()))?);
        }
        let job_seq = self.next_job_seq;
        self.next_job_seq += 1;
        let mut job = Job { job_seq, envelope: Bytes(envelope_frame.to_vec()), key_version: kv, items, prod_time: now, sealed: Sealed { enc: Bytes::default(), ct: Bytes::default() } };
        let aad = aad_of(b"chp-job-aad-v1", &job);
        let s = seal(&wrap.0, b"chp-job-v1", &aad, &encode(&frags), &mut rand::thread_rng()).map_err(|e| Refusal::Other(e.to_string()))?;
        job.sealed = Sealed { enc: Bytes(s.enc), ct: Bytes(s.ct) };
        self.outbox.insert(job_seq, job.clone());
        self.pending_env.insert(job_seq, (env, decoded, now));
        self.send(MsgType::Job, &job);
        Ok(job_seq)
    }

    /// Periodic work: abort `Pending` batches past their `import_deadline`.
    pub fn poll(&mut self, now: u64) {
        let late: Vec<B32> = self.batches.iter().filter(|(_, b)| b.st == PBatch::Pending && now > b.import_deadline).map(|(k, _)| *k).collect();
        for b in late {
            self.abort_local(&b);
        }
    }

    /// Report pool levels to COLD (DESIGN SP7 §2).
    pub fn send_pool_status(&mut self) {
        let pools: Vec<PoolId> = self.pools.keys().cloned().collect();
        for p in pools {
            let available: Vec<PresigId> = self.pools[&p].keys().copied().filter(|i| self.is_active(&p, *i)).collect();
            let high_water = *self.high_water.get(&p).unwrap_or(&0);
            let active_batches: Vec<B32> = self.batches.iter().filter(|(_, b)| b.st == PBatch::Active && b.pool == p).map(|(k, _)| *k).collect();
            self.send(MsgType::PoolStatus, &PoolStatus { pool: p, available, high_water, active_batches });
        }
    }

    // ------------------------------------------------------------------ SP10 ------------

    /// Answer an `AddressQuery` with a signed `AddressProof` or `NotFound` (DESIGN SP10 §3).
    pub fn address_query(&mut self, frame: &[u8], now: u64) -> Result<Vec<u8>, Refusal> {
        let signer = signer_of(frame).map_err(|e| Refusal::Other(e.to_string()))?;
        let cert = self.clients.get(&signer).cloned().ok_or(Refusal::Other("requester not enrolled".into()))?;
        if now > cert.not_after || now < cert.not_before {
            return Err(Refusal::Other("requester certificate outside its validity window".into()));
        }
        let (_, body) = check_standalone(&cert, Role::Prod, frame, MsgType::AddressQuery).map_err(|e| Refusal::Other(e.to_string()))?;
        let q: AddressQuery = decode_canonical(&body).map_err(|e| Refusal::Other(e.to_string()))?;
        if now > q.not_after || q.not_after > now + 300 || !self.query_replay.check_and_insert(q.nonce, q.not_after, now) {
            return Err(Refusal::Other("expired or replayed query".into()));
        }
        let found = self.book.find(&q.chain, q.address.as_deref(), q.path.as_deref()).map(|(e, b, k, v)| (e.clone(), b.to_vec(), k, v));
        let manifest = found.as_ref().and_then(|(_, _, k, v)| self.keyring.get(k, *v)).map(|k| k.manifest_bytes.clone());
        match (found, manifest) {
            (Some((entry, book, _, _)), Some(manifest)) => {
                let p = AddressProof { nonce: q.nonce, request_id: q.request_id, entry, book: Bytes(book), manifest: Bytes(manifest), prod_cert: Bytes(self.cert.clone()) };
                Ok(sign_body(&self.enclave.id, MsgType::AddressProof, 0, &p))
            }
            _ => Ok(sign_body(&self.enclave.id, MsgType::NotFound, 0, &NotFound { nonce: q.nonce, request_id: q.request_id })),
        }
    }

    // ------------------------------------------------------------------ control ---------

    /// Apply a public quorum-signed object. PROD refuses any key material.
    pub fn apply_quorum(&mut self, bytes: &[u8], now: u64) -> Result<(), Refusal> {
        let e = |x: String| Refusal::Other(x);
        let q: QuorumSignedMsg = decode_canonical(bytes).map_err(|x| e(x.to_string()))?;
        let t = MsgType::from_code(q.msg_type).ok_or(e("unknown type".into()))?;
        match t {
            MsgType::SharePackage => return Err(e("PROD refuses any SharePackage, even quorum-signed".into())),
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
                self.pools.retain(|p, _| !(p.key_id == c.key_id && p.key_version == c.key_version));
            }
            MsgType::Unfreeze => {
                let c = self.keyring.apply_unfreeze(&mut self.trust, bytes).map_err(|x| e(x.to_string()))?;
                self.events.push(Event::Unfrozen { key_id: c.key_id });
            }
            MsgType::RevocationList => {
                let newly = self.trust.apply_revocation(bytes).map_err(|x| e(x.to_string()))?;
                // Every pool involves HOT's, COLD's and PROD's side: revoking any of them discards
                // all pools; revoking a client or an unrelated key discards nothing.
                // A hash alone does not say whether an unlinked key was a COLD or HOT (security
                // review: the compromised COLD is usually the disconnected one), so anything that
                // is not a known client discards conservatively.
                // Revocation entries carry the role: revoking HOT, COLD or PROD discards every
                // pool (even when that COLD is not linked); clients/custodians discard nothing.
                let discard = newly.iter().any(|r| r.is_share_side());
                let hashes: Vec<B32> = newly.iter().map(|r| r.key_hash).collect();
                for h in &hashes {
                    self.clients.remove(h);
                }
                if self.cold.as_ref().is_some_and(|l| hashes.contains(&l.peer_signer)) {
                    self.cold = None;
                }
                if discard {
                    self.pools.clear();
                    self.events.push(Event::PoolDiscarded { path: "*".into(), reason: "party revoked".into() });
                }
            }
            MsgType::PolicyBundle => {
                let pb: PolicyBundle = self.trust.verify_quorum(bytes, MsgType::PolicyBundle).map_err(|x| e(x.to_string()))?;
                if pb.target != Role::Prod {
                    return Err(e("PolicyBundle addressed to another party".into()));
                }
                if self.keyring.current(&pb.key_id).is_none() {
                    return Err(e("PolicyBundle for an unknown key".into()));
                }
                self.trust.bump_version(&format!("policy/{}", hex::encode(pb.key_id.0)), pb.version).map_err(|x| e(x.to_string()))?;
                self.policy.entry(pb.key_id).or_default().install(pb.version, pb.rules);
            }
            MsgType::AddressBook => {
                let b: AddressBook = self.trust.verify_quorum(bytes, MsgType::AddressBook).map_err(|x| e(x.to_string()))?;
                let k = self.keyring.get(&b.key_id, b.key_version).ok_or(e("unknown key".into()))?;
                let (m, h) = (k.manifest.clone(), k.manifest_hash);
                self.book.install(&self.trust, bytes, &m, &h).map_err(|x| e(x.to_string()))?;
            }
            MsgType::PartyCert => {
                let (c, _) = self.trust.verify_cert(bytes, now).map_err(|x| e(x.to_string()))?;
                if !matches!(c.role, Role::Upstream | Role::Requester) {
                    return Err(e("PROD enrolls UPSTREAM and requesters only".into()));
                }
                self.clients.insert(B32(chp_crypto::ident::key_hash(&c.id_pk.0)), c);
            }
            other => return Err(e(format!("{other:?} not accepted"))),
        }
        Ok(())
    }
}

/// Reconstruct the key id of a pool (for display).
pub fn pool_key(p: &PoolId) -> KeyId {
    p.key_id
}
