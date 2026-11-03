//! HOT engine (DESIGN SP3, SP4, SP5; role table in DESIGN §3).
//!
//! HOT holds a key share, is powered off by default and is reachable only through the link
//! COLD opens inside an agreed wake window. It can: accept a wake window, apply relayed quorum
//! files, answer COLD's presign sessions, export sealed halves for PROD, and join a
//! quorum-opened ceremony. It cannot: receive requests, send jobs, talk to PROD over a network,
//! or start any key operation.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use chp_auth::{
    link::{accept_hello, make_hello, HelloParams, Link},
    sign_body,
    trust::{Pinned, Trust},
};
use chp_core::{
    address::BookView,
    digest::{aad_of, batch_digest, wake_digest},
    keyring::Keyring,
    Event, Out,
};
use chp_crypto::{ecdsa::EcdsaHalf, seal::seal};
use chp_mpc::{presign::BatchRun, share_from_bytes, share_to_bytes, Keyshare};
use chp_tee::Enclave;
use chp_wire::{
    decode_canonical, encode,
    msgs::*,
    Bytes, Fault, KeyId, MsgType, PoolId, QuorumSignedMsg, Role, B32,
};

/// Deployer mode (DESIGN §6.2): which return stage a wake window may request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Standard,
    HighSecurity,
}

#[derive(Clone, Debug)]
pub struct HotConfig {
    pub mode: Mode,
    pub replica: u8,
    /// Caps a `WakeOpen` must respect.
    pub max_batches_cap: u32,
    pub max_window_secs: u64,
}

const WAKE_COUNTER: &str = "wake";
const MAX_BATCH: usize = 256;

#[derive(Debug)]
enum Wake {
    /// Powered off / booted locked: only COLD's hello and `WakeOpen`.
    Locked,
    /// `WakeOpen` checked, counter advanced, waiting for HOT's operator to confirm the digest.
    Proposed { w: WakeOpen, digest: B32 },
    Open { w: WakeOpen, batches: u32 },
}

/// A pending HPKE share package import (ceremony mode).
#[derive(Debug, Clone)]
pub struct CeremonyMode {
    pub open: CeremonyOpen,
}

pub struct Hot {
    cfg: HotConfig,
    pub enclave: Enclave,
    pub trust: Trust,
    cert: Vec<u8>,
    pub keyring: Keyring,
    pub book: BookView,
    shares: BTreeMap<(KeyId, u32), Arc<Keyshare>>,
    prod_cert: Option<(PartyCert, Vec<u8>)>,
    pool_last: BTreeMap<PoolId, u64>,
    used_batches: BTreeSet<B32>,
    link: Option<Link>,
    wake: Wake,
    ceremony: Option<CeremonyMode>,
    runs: BTreeMap<B32, (PresignOpen, BatchRun)>,
    pub out: Vec<Out>,
    pub events: Vec<Event>,
}

#[derive(Debug, thiserror::Error)]
pub enum HotError {
    #[error("refused: {0}")]
    Refused(String),
}

fn refuse<T>(s: impl Into<String>) -> Result<T, HotError> {
    Err(HotError::Refused(s.into()))
}

impl Hot {
    pub fn new(cfg: HotConfig, enclave: Enclave, pinned: &Pinned) -> Self {
        Hot {
            cfg,
            enclave,
            trust: Trust::new(pinned),
            cert: Vec::new(),
            keyring: Keyring::default(),
            book: BookView::default(),
            shares: BTreeMap::new(),
            prod_cert: None,
            pool_last: BTreeMap::new(),
            used_batches: BTreeSet::new(),
            link: None,
            wake: Wake::Locked,
            ceremony: None,
            runs: BTreeMap::new(),
            out: Vec::new(),
            events: Vec::new(),
        }
    }

    pub fn set_cert(&mut self, cert: Vec<u8>) {
        self.cert = cert;
    }
    pub fn cert(&self) -> &[u8] {
        &self.cert
    }
    pub fn wake_counter(&self) -> u64 {
        self.enclave.counters.read(WAKE_COUNTER)
    }
    pub fn is_open(&self) -> bool {
        matches!(self.wake, Wake::Open { .. })
    }
    pub fn has_share(&self, key_id: &KeyId, v: u32) -> bool {
        self.shares.contains_key(&(*key_id, v))
    }

    /// Power on, locked (DESIGN SP4 §2 step 2). Shows the wake counter to the operator.
    pub fn boot(&mut self) {
        self.wake = Wake::Locked;
        self.link = None;
        self.runs.clear();
        self.out.push(Out::Display(format!("HOT wake counter = {}", self.wake_counter())));
    }

    /// Power off: erase all session state (DESIGN SP4 §2 step 6).
    pub fn power_off(&mut self) {
        for (_, (_, mut r)) in std::mem::take(&mut self.runs) {
            r.abort();
        }
        self.wake = Wake::Locked;
        self.link = None;
        self.ceremony = None;
    }

    fn refused(&mut self, what: &str, why: impl Into<String>) {
        self.events.push(Event::Refused { what: what.into(), why: why.into() });
    }

    // ------------------------------------------------------------------ link ----------

    /// COLD dials; HOT answers. HOT accepts a hello only from COLD.
    pub fn on_hello(&mut self, bytes: &[u8], tls: B32, now: u64) -> Result<Vec<u8>, HotError> {
        let (link, h) = accept_hello(&mut self.trust, Role::Hot, now, bytes, tls, &[Role::Cold], None)
            .map_err(|e| HotError::Refused(e.to_string()))?;
        self.link = Some(link);
        Ok(make_hello(HelloParams {
            id: &self.enclave.id,
            cert: &self.cert,
            roster_updates: vec![],
            nonce: B32(rand::random()),
            peer_nonce: Some(h.nonce),
            keys: self.keyring.all().map(|e| (e.manifest.key_id, e.manifest.key_version)).collect(),
            policy_ver: None, // HOT ignores policy versions
            revocation_ver: self.trust.revocation_ver(),
            tls_binding: tls,
        }))
    }

    fn send(&mut self, t: MsgType, body: &impl serde::Serialize) {
        if let Some(l) = self.link.as_mut() {
            let b = l.seal(&self.enclave.id, t, body);
            self.out.push(Out::Send { to: Role::Cold, bytes: b });
        }
    }

    /// Handle one frame from COLD.
    pub fn on_frame(&mut self, bytes: &[u8], now: u64) {
        let Some(link) = self.link.as_mut() else {
            return self.refused("frame", "no link");
        };
        let (t, body) = match link.check(&self.trust, bytes) {
            Ok(x) => x,
            Err(e) => return self.refused("frame", e.to_string()),
        };
        let r = match t {
            MsgType::WakeOpen => self.on_wake_open(decode_canonical(&body).unwrap(), now),
            MsgType::WakeClose => {
                self.power_off();
                Ok(())
            }
            MsgType::QuorumFile => self.on_quorum_file(decode_canonical(&body).unwrap(), now),
            MsgType::PresignOpen => self.on_presign_open(decode_canonical(&body).unwrap(), now),
            MsgType::PresignMsg => self.on_presign_msg(decode_canonical(&body).unwrap()),
            MsgType::FreezeNotice => {
                let f: FreezeNotice = decode_canonical(&body).unwrap();
                if self.keyring.freeze(&f.key_id, f.key_version, f.fault) {
                    self.events.push(Event::Frozen { key_id: f.key_id, fault: f.fault });
                }
                Ok(())
            }
            other => refuse(format!("{other:?} not handled by HOT")),
        };
        if let Err(e) = r {
            self.refused(&format!("{t:?}"), e.to_string());
        }
    }

    // ------------------------------------------------------------------ wake ----------

    fn on_wake_open(&mut self, w: WakeOpen, now: u64) -> Result<(), HotError> {
        if !matches!(self.wake, Wake::Locked) {
            return refuse("window already proposed or open");
        }
        let allowed = match (self.cfg.mode, w.return_stage) {
            (_, ReturnStage::ControlOnly) => true,
            (Mode::Standard, ReturnStage::PresignSync) => true,
            (Mode::HighSecurity, ReturnStage::Dkg) => true,
            _ => false,
        };
        if !allowed {
            return refuse(format!("mode {:?} does not allow {:?}", self.cfg.mode, w.return_stage));
        }
        if w.return_stage == ReturnStage::PresignSync {
            match self.keyring.get(&w.key_id, w.key_version) {
                Some(e) if e.usable() => {}
                _ => return refuse("key not active or frozen"),
            }
        }
        if w.max_batches > self.cfg.max_batches_cap || w.not_after <= now || w.not_after > now + self.cfg.max_window_secs {
            return refuse("window caps exceeded");
        }
        let want = self.wake_counter() + 1;
        if w.wake_seq != want {
            return refuse(format!("wake_seq {} != counter + 1 = {want}", w.wake_seq));
        }
        // Advance the hardware counter *before* accepting: a replayed WakeOpen is refused even
        // if HOT's storage is restored while powered off.
        self.enclave.counters.increment(WAKE_COUNTER);
        let digest = wake_digest(&w);
        self.out.push(Out::Display(format!("HOT wake digest {}", hex::encode(&digest.0[..8]))));
        self.wake = Wake::Proposed { w, digest };
        Ok(())
    }

    /// HOT's operator confirms the digest shown on COLD matches (DESIGN SP4 §2 step 3).
    pub fn operator_confirm_wake(&mut self, digest_seen_on_cold: B32) -> Result<(), HotError> {
        let Wake::Proposed { w, digest } = &self.wake else { return refuse("no proposed window") };
        if *digest != digest_seen_on_cold {
            let _ = w;
            self.power_off();
            return refuse("digest mismatch: window never opens");
        }
        let (w, digest) = (w.clone(), *digest);
        self.wake = Wake::Open { w, batches: 0 };
        self.send(MsgType::WakeAccept, &WakeAccept { digest });
        Ok(())
    }

    fn window(&self) -> Option<&WakeOpen> {
        match &self.wake {
            Wake::Open { w, .. } => Some(w),
            _ => None,
        }
    }

    // ------------------------------------------------------------------ quorum files ----

    fn on_quorum_file(&mut self, qf: QuorumFile, now: u64) -> Result<(), HotError> {
        if self.window().is_none() {
            return refuse("quorum files only inside a window");
        }
        self.apply_quorum_object(&qf.inner.0, now)
    }

    /// Apply a public quorum-signed object; HOT verifies the inner signature itself.
    pub fn apply_quorum_object(&mut self, inner: &[u8], now: u64) -> Result<(), HotError> {
        let q: QuorumSignedMsg = decode_canonical(inner).map_err(|e| HotError::Refused(e.to_string()))?;
        let t = MsgType::from_code(q.msg_type).ok_or(HotError::Refused("unknown type".into()))?;
        let e = |x: String| HotError::Refused(x);
        match t {
            MsgType::RosterUpdate => self.trust.apply_roster_update(inner).map(drop).map_err(|x| e(x.to_string())),
            MsgType::KeyManifest => self.keyring.install_manifest(&self.trust, inner).map(drop).map_err(|x| e(x.to_string())),
            MsgType::Activate => self.keyring.apply_activate(&mut self.trust, inner).map(drop).map_err(|x| e(x.to_string())),
            MsgType::Retire => {
                let c = self.keyring.apply_retire(&mut self.trust, inner).map_err(|x| e(x.to_string()))?;
                self.pool_last.retain(|p, _| !(p.key_id == c.key_id && p.key_version == c.key_version));
                Ok(())
            }
            MsgType::Unfreeze => {
                let c = self.keyring.apply_unfreeze(&mut self.trust, inner).map_err(|x| e(x.to_string()))?;
                self.events.push(Event::Unfrozen { key_id: c.key_id });
                Ok(())
            }
            MsgType::RevocationList => {
                self.trust.apply_revocation(inner).map_err(|x| e(x.to_string()))?;
                if let Some((c, _)) = &self.prod_cert {
                    if self.trust.is_revoked(&B32(chp_crypto::ident::key_hash(&c.id_pk.0))) {
                        self.prod_cert = None;
                    }
                }
                Ok(())
            }
            MsgType::AddressBook => {
                let b: AddressBook = self.trust.verify_quorum(inner, MsgType::AddressBook).map_err(|x| e(x.to_string()))?;
                let k = self.keyring.get(&b.key_id, b.key_version).ok_or(e("unknown key".into()))?;
                let (m, h) = (k.manifest.clone(), k.manifest_hash);
                self.book.install(&self.trust, inner, &m, &h).map_err(|x| e(x.to_string()))
            }
            MsgType::PartyCert => {
                let (c, _) = self.trust.verify_cert(inner, now).map_err(|x| e(x.to_string()))?;
                if c.role != Role::Prod {
                    return refuse("HOT only stores PROD's certificate");
                }
                self.prod_cert = Some((c, inner.to_vec()));
                Ok(())
            }
            other => refuse(format!("{other:?} is not accepted as a quorum file")),
        }
    }

    // ------------------------------------------------------------------ presign ---------

    fn on_presign_open(&mut self, o: PresignOpen, now: u64) -> Result<(), HotError> {
        let reason = self.presign_accept_check(&o, now);
        if let Some(reason) = reason {
            self.send(MsgType::PresignRefuse, &PresignRefuse { batch_id: o.batch_id, reason });
            return Ok(());
        }
        let share = self.shares[&(o.key_id, o.key_version)].clone();
        self.used_batches.insert(o.batch_id);
        let pool = PoolId { key_id: o.key_id, key_version: o.key_version, path: o.path.clone() };
        self.pool_last.insert(pool, *o.presig_ids.last().unwrap());
        if let Wake::Open { batches, .. } = &mut self.wake {
            *batches += 1;
        }
        let run = BatchRun::start(share, o.batch_id.0, &o.presig_ids);
        self.runs.insert(o.batch_id, (o.clone(), run));
        self.send(MsgType::PresignAccept, &PresignAccept { batch_id: o.batch_id });
        Ok(())
    }

    /// HOT's acceptance checks (DESIGN SP4 §4 step 2). `None` = accept.
    fn presign_accept_check(&self, o: &PresignOpen, now: u64) -> Option<RefuseReason> {
        let Wake::Open { w, batches } = &self.wake else { return Some(RefuseReason::WindowClosed) };
        if w.return_stage == ReturnStage::ControlOnly || *batches >= w.max_batches || now > w.not_after {
            return Some(RefuseReason::WindowClosed);
        }
        let Some(k) = self.keyring.get(&o.key_id, o.key_version) else { return Some(RefuseReason::KeyNotActive) };
        if k.state != chp_wire::KeyState::Active {
            return Some(RefuseReason::KeyNotActive);
        }
        if k.frozen.is_some() {
            return Some(RefuseReason::KeyFrozen);
        }
        if k.manifest.protocol != o.protocol || !self.shares.contains_key(&(o.key_id, o.key_version)) {
            return Some(RefuseReason::VersionMismatch);
        }
        if !self.book.path_active(&o.key_id, &o.path) {
            return Some(RefuseReason::PathNotInBook);
        }
        if o.presig_ids.is_empty() || o.presig_ids.len() > MAX_BATCH || self.used_batches.contains(&o.batch_id) || self.prod_cert.is_none() {
            return Some(RefuseReason::BadBatch);
        }
        if !o.presig_ids.windows(2).all(|p| p[0] < p[1])
            || o.presig_ids.iter().any(|id| chp_wire::presig_id::replicas(*id).0 != self.cfg.replica)
        {
            return Some(RefuseReason::BadBatch);
        }
        let pool = PoolId { key_id: o.key_id, key_version: o.key_version, path: o.path.clone() };
        if let Some(last) = self.pool_last.get(&pool) {
            if o.presig_ids[0] <= *last {
                return Some(RefuseReason::IdReused);
            }
        }
        None
    }

    fn on_presign_msg(&mut self, m: PresignMsg) -> Result<(), HotError> {
        let Some((_, run)) = self.runs.get_mut(&m.batch_id) else { return refuse("unknown batch") };
        run.deliver(m.presig_id, m.payload.0).map_err(|e| HotError::Refused(e.to_string()))
    }

    /// Drive running presign batches: emit library messages and finish completed batches.
    pub async fn poll(&mut self, now: u64) {
        if let Wake::Open { w, .. } = &self.wake {
            if now > w.not_after {
                self.send(MsgType::WakeClose, &WakeClose { reason: "deadline".into() });
                self.power_off();
                return;
            }
        }
        let ids: Vec<B32> = self.runs.keys().copied().collect();
        for b in ids {
            let msgs = self.runs.get_mut(&b).unwrap().1.drain_outgoing();
            for (id, payload) in msgs {
                self.send(MsgType::PresignMsg, &PresignMsg { batch_id: b, presig_id: id, payload: Bytes(payload) });
            }
            if self.runs[&b].1.is_finished() {
                let (o, run) = self.runs.remove(&b).unwrap();
                match run.finish().await {
                    Ok(halves) => self.export(o, halves),
                    Err(e) => {
                        // DESIGN SP4 §6: consistency failure → batch aborted, key frozen, no retry.
                        self.keyring.freeze(&o.key_id, o.key_version, Fault::Presign);
                        self.events.push(Event::Frozen { key_id: o.key_id, fault: Fault::Presign });
                        self.events.push(Event::Info(format!("presign fault: {e}")));
                        self.send(MsgType::FreezeNotice, &FreezeNotice { key_id: o.key_id, key_version: o.key_version, fault: Fault::Presign, evidence_hash: o.batch_id });
                        self.send(MsgType::WakeClose, &WakeClose { reason: "presign fault".into() });
                        self.power_off();
                        return;
                    }
                }
            }
        }
    }

    /// SP5 steps 2–4: seal halves to PROD, sign the transfer, erase, report `PresignStored`.
    fn export(&mut self, o: PresignOpen, halves: Vec<(u64, EcdsaHalf)>) {
        let parts: Vec<(u64, Vec<u8>)> = halves.iter().map(|(id, h)| (*id, h.public_part())).collect();
        let digest = batch_digest(&o.batch_id, &o.key_id, o.key_version, &o.path, &parts);
        let Some((prod, _)) = self.prod_cert.clone() else { return };
        let plaintext = encode(&halves);
        let mut tr = PresigTransfer {
            batch_id: o.batch_id,
            key_id: o.key_id,
            key_version: o.key_version,
            path: o.path.clone(),
            presig_ids: o.presig_ids.clone(),
            import_deadline: o.import_deadline,
            digest,
            sealed: Sealed { enc: Bytes::default(), ct: Bytes::default() },
        };
        let aad = aad_of(b"chp-transfer-aad-v1", &tr);
        let s = seal(&prod.wrap_pk.0, b"chp-transfer-v1", &aad, &plaintext, &mut rand::thread_rng()).expect("seal");
        tr.sealed = Sealed { enc: Bytes(s.enc), ct: Bytes(s.ct) };
        let transfer = sign_body(&self.enclave.id, MsgType::PresigTransfer, 0, &tr);
        let bundle = MediaBundle { hot_cert: Bytes(self.cert.clone()), transfer: Bytes(transfer) };
        drop(halves); // ERASE: halves are zeroized on drop; nothing is kept for the batch.
        drop(plaintext);
        self.out.push(Out::Media(encode(&bundle)));
        self.send(MsgType::PresignStored, &PresignStored { batch_id: o.batch_id, digest });
    }

    // ------------------------------------------------------------------ ceremony --------

    /// Ceremony boot (DESIGN SP4 "Ceremony boot"): quorum-signed `CeremonyOpen`,
    /// `boot_seq[Hot]` = wake counter + 1, counter advanced, then only that ceremony's messages.
    pub fn ceremony_boot(&mut self, open: &[u8], now: u64) -> Result<CeremonyOpen, HotError> {
        let o: CeremonyOpen = self.trust.verify_quorum(open, MsgType::CeremonyOpen).map_err(|e| HotError::Refused(e.to_string()))?;
        if now > o.not_after || !o.participants.contains(&Role::Hot) {
            return refuse("ceremony expired or HOT not a participant");
        }
        let want = self.wake_counter() + 1;
        if !o.boot_seq.contains(&(Role::Hot, want)) {
            return refuse(format!("boot_seq[Hot] != {want}"));
        }
        self.enclave.counters.increment(WAKE_COUNTER);
        self.ceremony = Some(CeremonyMode { open: o.clone() });
        Ok(o)
    }

    /// SP3 import (ceremony mode only): quorum sigs, manifest hash, own index, HPKE open with
    /// the expected `info`, `s_i·G == Y_i`, then seal. Returns the signed `ShareReceipt`.
    pub fn import_share(&mut self, manifest: &[u8], package: &[u8]) -> Result<Vec<u8>, HotError> {
        let Some(cm) = &self.ceremony else { return refuse("share packages only in ceremony mode") };
        let e = |x: String| HotError::Refused(x);
        let entry = self.keyring.install_manifest(&self.trust, manifest).map_err(|x| e(x.to_string()))?.clone();
        let p: SharePackage = self.trust.verify_quorum(package, MsgType::SharePackage).map_err(|x| e(x.to_string()))?;
        let my_index = chp_mpc::dkls::PARTY_HOT;
        if p.manifest_hash != entry.manifest_hash || p.party_index != my_index || p.key_id != entry.manifest.key_id || p.key_version != entry.manifest.key_version {
            return refuse("package does not match manifest / party");
        }
        if p.ceremony_id != cm.open.ceremony_id {
            return refuse("package from another ceremony");
        }
        if self.shares.contains_key(&(p.key_id, p.key_version)) {
            return refuse("already imported (forward-only)");
        }
        let info = share_info(&p);
        let sealed = chp_crypto::seal::Sealed { enc: p.sealed.enc.0.clone(), ct: p.sealed.ct.0.clone() };
        let bytes = self.enclave.wrap.open(&sealed, &info, &[]).map_err(|x| e(x.to_string()))?;
        let share = share_from_bytes(&bytes).ok_or(e("bad share encoding".into()))?;
        let my_pub = entry.manifest.parties.iter().find(|x| x.role == Role::Hot).ok_or(e("no HOT entry".into()))?;
        if chp_crypto::ecdsa::enc_point(&share.big_s(share.party_id)).to_vec() != my_pub.public_share.0
            || chp_crypto::ecdsa::enc_point(&share.public_key()).to_vec() != entry.manifest.group_key.0
        {
            return refuse("s_i·G != Y_i: share does not match manifest");
        }
        let _ = share_to_bytes; // sealed in the simulated enclave (kept in memory here)
        self.shares.insert((p.key_id, p.key_version), Arc::new(share));
        let receipt = ShareReceipt {
            key_id: p.key_id,
            key_version: p.key_version,
            party_index: my_index,
            public_share: my_pub.public_share.clone(),
            measurement: self.enclave.measurement,
            manifest_hash: entry.manifest_hash,
        };
        Ok(sign_body(&self.enclave.id, MsgType::ShareReceipt, 0, &receipt))
    }

    /// Leave ceremony mode and power off.
    pub fn end_ceremony(&mut self) {
        self.ceremony = None;
        self.power_off();
    }
}

/// HPKE `info` of a share package (DESIGN SP3 §4 step 1).
pub fn share_info(p: &SharePackage) -> Vec<u8> {
    let mut v = b"chp-share-v1".to_vec();
    v.extend_from_slice(&p.key_id.0);
    v.extend_from_slice(&p.key_version.to_be_bytes());
    v.push(p.party_index);
    v.extend_from_slice(&p.ceremony_id.0);
    v
}
