//! SP1 · Identity & authorization (DESIGN SP1).
//!
//! * [`matrix`] — who may send which message type to whom (SP1 §6).
//! * [`trust`]  — pinned roots, current rosters, revocation, quorum verification, certificates,
//!   anti-rollback of control objects (SP1 §2, §3, §7, §8).
//! * [`link`]   — `LinkHello` handshake and the 6-step frame check (SP1 §4, §5).
//! * [`quorum`] — quorum signing tool (offline custodians).

pub mod link;
pub mod matrix;
pub mod quorum;
pub mod trust;

use chp_wire::{MsgType, WireError};

/// Why a frame or object was refused. Refusals change no state.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum AuthError {
    #[error("step 1: unknown message type {0}")]
    UnknownType(u16),
    #[error("step 2: signer is not the linked peer")]
    WrongSigner,
    #[error("step 3: sequence {got}, expected {want}")]
    BadSeq { got: u64, want: u64 },
    #[error("step 4: role {role:?} may not send {t:?} to {to:?}")]
    RoleNotAllowed { role: chp_wire::Role, t: MsgType, to: chp_wire::Role },
    #[error("step 5: bad signature")]
    BadSignature,
    #[error("step 6: body: {0}")]
    Body(WireError),
    #[error("frame: {0}")]
    Frame(WireError),
    #[error("quorum: {0}")]
    Quorum(String),
    #[error("certificate: {0}")]
    Cert(String),
    #[error("revoked")]
    Revoked,
    #[error("rollback: version {got} not above {last}")]
    Rollback { got: u64, last: u64 },
    #[error("handshake: {0}")]
    Handshake(String),
    #[error("expected type {want:?}, got {got:?}")]
    WrongType { want: MsgType, got: MsgType },
}

pub type Result<T> = std::result::Result<T, AuthError>;

/// Signature input of a `SignedMsg`: `"chp-v1" ‖ type ‖ seq ‖ SHA-256(body)` (SP1 §5).
pub fn signed_msg_input(t: u16, seq: u64, body: &[u8]) -> Vec<u8> {
    let mut m = b"chp-v1".to_vec();
    m.extend_from_slice(&t.to_be_bytes());
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(&chp_crypto::hash::sha256(body));
    m
}

/// Signature input of a frame on an installed link: also binds the link session id, so a frame
/// from an earlier session can never be replayed into a later one (security review round 2).
pub fn link_msg_input(link_id: &[u8; 32], t: u16, seq: u64, body: &[u8]) -> Vec<u8> {
    let mut m = b"chp-link-v1".to_vec();
    m.extend_from_slice(link_id);
    m.extend_from_slice(&t.to_be_bytes());
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(&chp_crypto::hash::sha256(body));
    m
}

/// Sign a `SignedMsg` with an enclave identity key.
pub fn sign_msg(id: &chp_crypto::ident::IdKey, t: MsgType, seq: u64, body: Vec<u8>) -> chp_wire::SignedMsg {
    let sig = id.sign(&signed_msg_input(t.code(), seq, &body));
    chp_wire::SignedMsg {
        msg_type: t.code(),
        seq,
        body: chp_wire::Bytes(body),
        signer: chp_wire::B32(chp_crypto::ident::key_hash(&id.public())),
        sig: chp_wire::B64(sig),
    }
}

/// Sign a frame for an installed link with session id `link_id` (what [`link::Link::seal`]
/// does; exposed for tests that craft frames).
pub fn sign_link(id: &chp_crypto::ident::IdKey, link_id: &[u8; 32], t: MsgType, seq: u64, body: Vec<u8>) -> chp_wire::SignedMsg {
    let sig = id.sign(&link_msg_input(link_id, t.code(), seq, &body));
    chp_wire::SignedMsg {
        msg_type: t.code(),
        seq,
        body: chp_wire::Bytes(body),
        signer: chp_wire::B32(chp_crypto::ident::key_hash(&id.public())),
        sig: chp_wire::B64(sig),
    }
}

/// Encode a body and sign it as a standalone `SignedMsg` (API messages, media, receipts).
pub fn sign_body<T: serde::Serialize>(id: &chp_crypto::ident::IdKey, t: MsgType, seq: u64, body: &T) -> Vec<u8> {
    chp_wire::encode(&sign_msg(id, t, seq, chp_wire::encode(body)))
}
