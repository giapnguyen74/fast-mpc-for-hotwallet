//! Frames and the closed message registry (DESIGN SP1 §5–§7).

use serde::{Deserialize, Serialize};

use crate::types::*;

/// The closed registry. Anything not listed here does not exist (DESIGN SP1 §6).
/// Encoded on the wire as `u16`; an unknown code is refused at step 1.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
#[repr(u16)]
pub enum MsgType {
    // SP1
    LinkHello = 1,
    PartyCert = 2,
    RosterUpdate = 3,
    RevocationList = 4,
    // SP2/SP3/SP8
    CeremonyOpen = 10,
    KeyManifest = 11,
    SharePackage = 12,
    ShareReceipt = 13,
    Activate = 14,
    Retire = 15,
    CeremonyRound = 16,
    // SP4
    WakeOpen = 20,
    WakeAccept = 21,
    WakeClose = 22,
    QuorumFile = 23,
    PresignOpen = 24,
    PresignAccept = 25,
    PresignRefuse = 26,
    PresignMsg = 27,
    FrostCommitments = 28,
    PresignStored = 29,
    ShareMasks = 30,
    // SP5
    PresigTransfer = 40,
    MediaBundle = 41,
    TransferAck = 42,
    PresignActivate = 43,
    PresignAbort = 44,
    // SP6
    WithdrawalEnvelope = 50,
    Job = 51,
    Status = 52,
    // SP7
    FreezeNotice = 60,
    Unfreeze = 61,
    PolicyBundle = 62,
    PoolStatus = 63,
    OrphanDelete = 64,
    // SP9
    QrPairing = 70,
    // SP10
    AddressBook = 80,
    AddressQuery = 81,
    AddressProof = 82,
    NotFound = 83,
}

impl MsgType {
    pub const ALL: &'static [MsgType] = &[
        MsgType::LinkHello, MsgType::PartyCert, MsgType::RosterUpdate, MsgType::RevocationList,
        MsgType::CeremonyOpen, MsgType::KeyManifest, MsgType::SharePackage, MsgType::ShareReceipt,
        MsgType::Activate, MsgType::Retire, MsgType::CeremonyRound, MsgType::WakeOpen,
        MsgType::WakeAccept, MsgType::WakeClose, MsgType::QuorumFile, MsgType::PresignOpen,
        MsgType::PresignAccept, MsgType::PresignRefuse, MsgType::PresignMsg,
        MsgType::FrostCommitments, MsgType::PresignStored, MsgType::ShareMasks,
        MsgType::PresigTransfer, MsgType::MediaBundle, MsgType::TransferAck,
        MsgType::PresignActivate, MsgType::PresignAbort, MsgType::WithdrawalEnvelope, MsgType::Job,
        MsgType::Status, MsgType::FreezeNotice, MsgType::Unfreeze, MsgType::PolicyBundle,
        MsgType::PoolStatus, MsgType::OrphanDelete, MsgType::QrPairing, MsgType::AddressBook,
        MsgType::AddressQuery, MsgType::AddressProof, MsgType::NotFound,
    ];

    pub fn code(self) -> u16 {
        self as u16
    }

    pub fn from_code(c: u16) -> Option<MsgType> {
        MsgType::ALL.iter().copied().find(|t| t.code() == c)
    }

    /// The link stream a type travels on (DESIGN SP1 §5 step 3: A jobs, B wake/presign/quorum
    /// files, C control). `None`: not a link message (quorum objects, media, API, ceremony).
    pub fn stream(self) -> Option<Stream> {
        use MsgType::*;
        Some(match self {
            Job | Status => Stream::A,
            WakeOpen | WakeAccept | WakeClose | QuorumFile | PresignOpen | PresignAccept
            | PresignRefuse | PresignMsg | FrostCommitments | PresignStored | ShareMasks => Stream::B,
            TransferAck | PresignActivate | PresignAbort | FreezeNotice | PoolStatus | OrphanDelete => {
                Stream::C
            }
            LinkHello => Stream::Hello,
            _ => return None,
        })
    }
}

/// Link streams.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Stream {
    /// `LinkHello` only, seq 0.
    Hello,
    A,
    B,
    C,
}

impl Stream {
    pub fn index(self) -> usize {
        match self {
            Stream::Hello => 0,
            Stream::A => 1,
            Stream::B => 2,
            Stream::C => 3,
        }
    }
}

/// `SignedMsg { type, seq, body, signer, sig }` with
/// `sig = Ed25519(id_key, "chp-v1" ‖ type ‖ seq ‖ SHA-256(body))`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedMsg {
    pub msg_type: u16,
    pub seq: u64,
    pub body: Bytes,
    /// `SHA-256(id_pk)` of the signer.
    pub signer: B32,
    pub sig: B64,
}

/// One quorum member's signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QSig {
    /// Member public key (Ed25519).
    pub member: B32,
    pub sig: B64,
}

/// `QuorumSignedMsg { type, body, sigs[] }` (DESIGN SP1 §7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumSignedMsg {
    pub msg_type: u16,
    pub body: Bytes,
    pub sigs: Vec<QSig>,
}
