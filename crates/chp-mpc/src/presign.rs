//! One side of a presign batch (DESIGN SP4 §4 step 3): one DKLs23 presign instance per
//! `presig_id`, instance id `H("chp-presign-v1" ‖ batch_id ‖ presig_id)`.
//!
//! Sans-I/O from the caller's point of view: library messages come out of
//! [`BatchRun::drain_outgoing`] (to be framed as `PresignMsg`), verified peer messages go in
//! through [`BatchRun::deliver`]. The library itself runs on tokio tasks.

use std::{collections::BTreeMap, sync::Arc};

use chp_crypto::{ecdsa::EcdsaHalf, CryptoError};
use sl_dkls23::keygen::Keyshare;
use tokio::{sync::mpsc, task::JoinHandle};

use crate::{
    dkls::{bridge, presign, presign_instance, PARTY_COLD, PARTY_HOT},
    half_from_presign,
};

struct Instance {
    outgoing: mpsc::UnboundedReceiver<Vec<u8>>,
    incoming: mpsc::UnboundedSender<Vec<u8>>,
    handle: Option<JoinHandle<Result<sl_dkls23::sign::PreSign, CryptoError>>>,
}

/// A running presign batch on one side (HOT or COLD).
pub struct BatchRun {
    pub batch_id: [u8; 32],
    inst: BTreeMap<u64, Instance>,
}

impl BatchRun {
    /// Start one library instance per id. Must be called inside a tokio runtime.
    pub fn start(share: Arc<Keyshare>, batch_id: [u8; 32], ids: &[u64]) -> Self {
        assert!(ids.windows(2).all(|w| w[0] < w[1]), "presig ids must be strictly increasing");
        let mut inst = BTreeMap::new();
        for &id in ids {
            let (relay, end) = bridge();
            let share = share.clone();
            let handle = tokio::spawn(presign(share, [PARTY_HOT, PARTY_COLD], presign_instance(&batch_id, id), rand::random(), relay));
            inst.insert(id, Instance { outgoing: end.outgoing, incoming: end.incoming, handle: Some(handle) });
        }
        BatchRun { batch_id, inst }
    }

    /// Library messages produced since the last call, tagged with their presig id.
    pub fn drain_outgoing(&mut self) -> Vec<(u64, Vec<u8>)> {
        let mut out = Vec::new();
        for (id, i) in self.inst.iter_mut() {
            while let Ok(m) = i.outgoing.try_recv() {
                out.push((*id, m));
            }
        }
        out
    }

    /// Deliver a verified peer message for instance `id`.
    pub fn deliver(&mut self, id: u64, payload: Vec<u8>) -> Result<(), CryptoError> {
        let i = self.inst.get(&id).ok_or(CryptoError::Mpc(format!("unknown presig id {id}")))?;
        i.incoming.send(payload).map_err(|_| CryptoError::Mpc("instance finished".into()))
    }

    /// All instances finished (successfully or not)? Callers must check this **before** the
    /// final `drain_outgoing`, so the last messages of an instance that finishes in between are
    /// not lost (security review).
    pub fn is_finished(&self) -> bool {
        self.inst.values().all(|i| i.handle.as_ref().map(|h| h.is_finished()).unwrap_or(true))
    }

    /// Abort every instance (link loss, operator cancel, fault elsewhere in the batch).
    pub fn abort(&mut self) {
        for i in self.inst.values_mut() {
            if let Some(h) = i.handle.take() {
                h.abort();
            }
        }
    }

    /// Collect the halves. Any failed instance fails the whole batch: DKLs23 R3 consistency
    /// failures are faults (DESIGN SP4 §6: key frozen, no retry).
    pub async fn finish(mut self) -> Result<Vec<(u64, EcdsaHalf)>, CryptoError> {
        let mut out = Vec::new();
        let mut err = None;
        for (id, i) in self.inst.iter_mut() {
            let h = i.handle.take().ok_or(CryptoError::Mpc("already taken".into()))?;
            match h.await {
                Ok(Ok(mut p)) => {
                    out.push((*id, half_from_presign(&p)));
                    zeroize::Zeroize::zeroize(&mut p); // the library's copy of the half
                }
                Ok(Err(e)) => err = Some(e),
                Err(e) => err = Some(CryptoError::Mpc(e.to_string())),
            }
        }
        match err {
            Some(e) => Err(e),
            None => Ok(out),
        }
    }
}

impl Drop for BatchRun {
    fn drop(&mut self) {
        self.abort();
    }
}
