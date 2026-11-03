//! Bridge between the vendored DKLs23 library (`thirdparty/dkls23`) and CHP transports.
//!
//! The library speaks through a pull-style [`Relay`]. CHP never lets the library touch a
//! network: [`BridgeRelay`] hands every outgoing library message to the caller (which wraps
//! it in a signed CHP frame, DESIGN SP1 §5) and receives incoming library messages only
//! after the caller has verified the CHP frame. Library "ask" messages are local and dropped:
//! the CHP side pushes every message to every other participant, and the library ignores
//! messages it did not ask for.
//!
//! Library-level message signing is disabled (`NoSigningKey`): authentication is the CHP
//! frame signature (enclave identity key), checked before the bytes reach the library.

use std::{
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use futures::{Sink, Stream};
use sl_dkls23::{
    keygen::{key_refresh::KeyshareForRefresh, Keyshare},
    setup::{keygen::SetupMessage as KeygenSetup, sign::SetupMessage as SignSetup, NoSigningKey, NoVerifyingKey},
    sign::PreSign,
    InstanceId, Relay,
};
use sl_mpc_mate::{coord::MessageSendError, message::MESSAGE_HEADER_SIZE};
use tokio::sync::mpsc;

use crate::{hash::tagged_hash, CryptoError};

/// Fixed library party ids (DESIGN SP2: HOT, COLD, REC with equal standing).
pub const PARTY_HOT: u8 = 0;
pub const PARTY_COLD: u8 = 1;
pub const PARTY_REC: u8 = 2;

const TTL: Duration = Duration::from_secs(600);

/// Library relay backed by channels. Outgoing messages go to `out`; incoming from `inbox`.
pub struct BridgeRelay {
    inbox: mpsc::UnboundedReceiver<Vec<u8>>,
    out: mpsc::UnboundedSender<Vec<u8>>,
}

/// The caller's end of a [`BridgeRelay`].
pub struct BridgeEnd {
    /// Library messages produced by this party (to be framed and sent).
    pub outgoing: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Deliver verified library messages from peers.
    pub incoming: mpsc::UnboundedSender<Vec<u8>>,
}

/// Create a relay and the caller's end.
pub fn bridge() -> (BridgeRelay, BridgeEnd) {
    let (in_tx, in_rx) = mpsc::unbounded_channel();
    let (out_tx, out_rx) = mpsc::unbounded_channel();
    (BridgeRelay { inbox: in_rx, out: out_tx }, BridgeEnd { outgoing: out_rx, incoming: in_tx })
}

impl Stream for BridgeRelay {
    type Item = Vec<u8>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        self.inbox.poll_recv(cx)
    }
}

impl Sink<Vec<u8>> for BridgeRelay {
    type Error = MessageSendError;
    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        if item.len() == MESSAGE_HEADER_SIZE {
            return Ok(()); // "ask" message: local only.
        }
        self.out.send(item).map_err(|_| MessageSendError)
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl Relay for BridgeRelay {}

/// DKLs23 instance id for one presignature: `H("chp-presign-v1" ‖ batch_id ‖ presig_id)`
/// (DESIGN SP4 §4 step 3).
pub fn presign_instance(batch_id: &[u8; 32], presig_id: u64) -> [u8; 32] {
    tagged_hash(b"chp-presign-v1", &[batch_id, &presig_id.to_be_bytes()])
}

/// Instance id for a ceremony (DKG / refresh) run.
pub fn ceremony_instance(ceremony_id: &[u8; 32], kind: &str) -> [u8; 32] {
    tagged_hash(b"chp-ceremony-v1", &[ceremony_id, kind.as_bytes()])
}

fn vks(n: usize) -> Vec<NoVerifyingKey> {
    (0..n).map(NoVerifyingKey::new).collect()
}

/// Run one party of a 2-of-3 DKG (DESIGN SP2 §4, DKLs23 key generation).
pub async fn keygen(party: u8, instance: [u8; 32], seed: [u8; 32], relay: BridgeRelay) -> Result<Keyshare, CryptoError> {
    let setup = KeygenSetup::new(InstanceId::new(instance), NoSigningKey, party as usize, vks(3), &[0, 0, 0], 2)
        .with_ttl(TTL);
    sl_dkls23::keygen::run(setup, seed, relay).await.map_err(|e| CryptoError::Mpc(format!("{e:?}")))
}

/// Run one party of a key refresh (DESIGN SP8 §2): fresh sharing of zero, same group key.
pub async fn refresh(
    share: &Keyshare,
    instance: [u8; 32],
    seed: [u8; 32],
    relay: BridgeRelay,
) -> Result<Keyshare, CryptoError> {
    let party = share.party_id as usize;
    let setup = KeygenSetup::new(InstanceId::new(instance), NoSigningKey, party, vks(3), &[0, 0, 0], 2)
        .with_ttl(TTL);
    let ks = KeyshareForRefresh::from_keyshare(share, None);
    sl_dkls23::keygen::key_refresh::run(setup, seed, relay, ks)
        .await
        .map_err(|e| CryptoError::Mpc(format!("{e:?}")))
}

/// Run one side of a 2-party presign at the library root path `m` (DESIGN SP4 §5).
///
/// `signers` lists the library party ids of the signer set in a fixed order (CHP uses
/// `[PARTY_HOT, PARTY_COLD]`); `share.party_id` must be one of them.
pub async fn presign(
    share: Arc<Keyshare>,
    signers: [u8; 2],
    instance: [u8; 32],
    seed: [u8; 32],
    relay: BridgeRelay,
) -> Result<PreSign, CryptoError> {
    let idx = signers
        .iter()
        .position(|p| *p == share.party_id)
        .ok_or(CryptoError::Mpc("party not in signer set".into()))?;
    let vk: Vec<NoVerifyingKey> = signers.iter().map(|p| NoVerifyingKey::new(*p as usize)).collect();
    let setup = SignSetup::new(InstanceId::new(instance), NoSigningKey, idx, vk, share)
        .with_chain_path(derivation_root())
        .with_ttl(TTL);
    sl_dkls23::sign::pre_signature(setup, seed, relay)
        .await
        .map_err(|e| CryptoError::Mpc(format!("{e:?}")))
}

fn derivation_root() -> sl_dkls23_derivation::DerivationPath {
    sl_dkls23_derivation::DerivationPath::from_str("m").expect("root path")
}

// The library takes `derivation_path::DerivationPath`; re-export through a private alias.
mod sl_dkls23_derivation {
    pub use derivation_path::DerivationPath;
}

/// In-process fan-out network for tests and the simulated ceremony network: every message
/// a party emits is delivered to every other party. Returns one relay per party and a task
/// that pumps messages until all relays are dropped.
pub fn local_mesh(n: usize) -> (Vec<BridgeRelay>, tokio::task::JoinHandle<()>) {
    let mut relays = Vec::new();
    let mut ends = Vec::new();
    for _ in 0..n {
        let (r, e) = bridge();
        relays.push(r);
        ends.push(e);
    }
    let incomings: Vec<_> = ends.iter().map(|e| e.incoming.clone()).collect();
    let mut outs: Vec<_> = ends.into_iter().map(|e| e.outgoing).collect();
    let task = tokio::spawn(async move {
        let mut futs = futures::stream::SelectAll::new();
        for (i, rx) in outs.drain(..).enumerate() {
            futs.push(Box::pin(futures::stream::unfold(rx, move |mut rx| async move {
                rx.recv().await.map(|m| ((i, m), rx))
            })));
        }
        use futures::StreamExt;
        while let Some((from, msg)) = futs.next().await {
            for (j, tx) in incomings.iter().enumerate() {
                if j != from {
                    let _ = tx.send(msg.clone());
                }
            }
        }
    });
    (relays, task)
}

/// Convenience for tests and the simulated ceremony: run a full 3-party DKG in-process.
pub async fn local_dkg(instance: [u8; 32]) -> Result<Vec<Keyshare>, CryptoError> {
    let (relays, pump) = local_mesh(3);
    let mut set = tokio::task::JoinSet::new();
    for (i, r) in relays.into_iter().enumerate() {
        let seed: [u8; 32] = rand::random();
        set.spawn(async move { keygen(i as u8, instance, seed, r).await });
    }
    let mut out = Vec::new();
    while let Some(r) = set.join_next().await {
        out.push(r.map_err(|e| CryptoError::Mpc(e.to_string()))??);
    }
    pump.abort();
    out.sort_by_key(|s| s.party_id);
    Ok(out)
}

/// Convenience for tests: run a 2-party presign in-process between two shares.
pub async fn local_presign(a: Arc<Keyshare>, b: Arc<Keyshare>, instance: [u8; 32]) -> Result<(PreSign, PreSign), CryptoError> {
    let (mut relays, pump) = local_mesh(2);
    let rb = relays.pop().unwrap();
    let ra = relays.pop().unwrap();
    let signers = [a.party_id, b.party_id];
    let fa = tokio::spawn(presign(a, signers, instance, rand::random(), ra));
    let fb = tokio::spawn(presign(b, signers, instance, rand::random(), rb));
    let pa = fa.await.map_err(|e| CryptoError::Mpc(e.to_string()))??;
    let pb = fb.await.map_err(|e| CryptoError::Mpc(e.to_string()))??;
    pump.abort();
    Ok((pa, pb))
}
