//! Message bodies of the closed registry (DESIGN SP1 §6 and the sub-protocol sections).
//!
//! Nested signed objects (certificates, forwarded envelopes, quorum files) are carried as the
//! exact encoded bytes of their `SignedMsg` / `QuorumSignedMsg`, so that every recipient
//! verifies the original signature itself.

use serde::{Deserialize, Serialize};

use crate::types::*;

// ---------------------------------------------------------------- SP1 identity -------------

/// Party certificate (DESIGN SP1 §3). Quorum-signed by the ceremony quorum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartyCert {
    pub role: Role,
    pub party_index: u8,
    pub replica: u8,
    pub id_pk: B32,
    pub wrap_pk: B32,
    pub measurement: B32,
    pub key_ids: Vec<KeyId>,
    pub not_before: u64,
    pub not_after: u64,
    /// COLD only: the fixed route of this replica (DESIGN SP9 §1).
    pub qr_route: bool,
}

/// Quorum roster (pinned in the image, or a quorum-signed `RosterUpdate`, DESIGN SP1 §2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roster {
    pub role: QuorumRole,
    pub version: u64,
    pub members: Vec<B32>,
    pub threshold: u8,
}

/// `RevocationList` (DESIGN SP1 §8): `SHA-256(id_pk)` of revoked keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationList {
    pub version: u64,
    pub revoked: Vec<B32>,
}

/// `LinkHello` (DESIGN SP1 §4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkHello {
    /// Encoded `QuorumSignedMsg<PartyCert>`.
    pub cert: Bytes,
    /// Encoded `QuorumSignedMsg<Roster>` chain the peer may not have.
    pub roster_updates: Vec<Bytes>,
    pub nonce: B32,
    pub peer_nonce: Option<B32>,
    pub keys: Vec<(KeyId, u32)>,
    pub policy_ver: Option<u64>,
    pub revocation_ver: u64,
    pub tls_binding: B32,
}

// ---------------------------------------------------------------- SP2/SP3 ceremony ---------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CeremonyKind {
    Dkg,
    Refresh,
    AddressSign,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeremonyOpen {
    pub ceremony_id: B32,
    pub kind: CeremonyKind,
    pub key_id: KeyId,
    pub key_version: u32,
    pub participants: Vec<Role>,
    pub not_after: u64,
    /// Next value of each participant's own boot counter.
    pub boot_seq: Vec<(Role, u64)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestParty {
    pub role: Role,
    pub party_index: u8,
    pub public_share: Bytes,
    pub cert_hash: B32,
}

/// `KeyManifest` (DESIGN SP2 §5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyManifest {
    pub key_id: KeyId,
    pub key_version: u32,
    pub protocol: Protocol,
    pub chain: String,
    pub group_key: Bytes,
    pub parties: Vec<ManifestParty>,
    pub ceremony_id: B32,
}

/// HPKE ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub enc: Bytes,
    pub ct: Bytes,
}

/// `SharePackage` (DESIGN SP3 §4). Quorum-signed. Never on a runtime link.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharePackage {
    pub key_id: KeyId,
    pub key_version: u32,
    pub party_index: u8,
    pub ceremony_id: B32,
    pub manifest_hash: B32,
    pub sealed: Sealed,
}

/// `ShareReceipt` (DESIGN SP3 §4 step 4). Enclave-signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareReceipt {
    pub key_id: KeyId,
    pub key_version: u32,
    pub party_index: u8,
    pub public_share: Bytes,
    pub measurement: B32,
    pub manifest_hash: B32,
}

/// `Activate` / `Retire` / `Unfreeze` share one shape (DESIGN SP3, SP7, SP8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyControl {
    pub key_id: KeyId,
    pub key_version: u32,
    /// Monotonic version of this control object (anti-replay, DESIGN SP1 §7).
    pub version: u64,
}

// ---------------------------------------------------------------- SP4 wake + presign -------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReturnStage {
    PresignSync,
    Dkg,
    ControlOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeOpen {
    pub key_id: KeyId,
    pub key_version: u32,
    pub return_stage: ReturnStage,
    pub max_batches: u32,
    pub not_after: u64,
    pub wake_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeAccept {
    pub digest: B32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeClose {
    pub reason: String,
}

/// Wrapper around one encoded `QuorumSignedMsg` relayed by COLD to HOT.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumFile {
    pub inner: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresignOpen {
    pub batch_id: B32,
    pub key_id: KeyId,
    pub key_version: u32,
    pub protocol: Protocol,
    pub presig_ids: Vec<PresigId>,
    pub path: String,
    pub import_deadline: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresignAccept {
    pub batch_id: B32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefuseReason {
    KeyNotActive,
    KeyFrozen,
    PathNotInBook,
    VersionMismatch,
    BadBatch,
    IdReused,
    WindowClosed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresignRefuse {
    pub batch_id: B32,
    pub reason: RefuseReason,
}

/// One MPC library message for one presignature instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresignMsg {
    pub batch_id: B32,
    pub presig_id: PresigId,
    pub payload: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresignStored {
    pub batch_id: B32,
    pub digest: B32,
}

// ---------------------------------------------------------------- SP5 media ---------------

/// `PresigTransfer` (DESIGN SP5 §3 step 2). Signed by HOT, seq 0.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresigTransfer {
    pub batch_id: B32,
    pub key_id: KeyId,
    pub key_version: u32,
    pub path: String,
    pub presig_ids: Vec<PresigId>,
    pub import_deadline: u64,
    pub digest: B32,
    pub sealed: Sealed,
}

/// `MediaBundle`: unsigned wrapper (HOT cert + signed transfer).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaBundle {
    pub hot_cert: Bytes,
    pub transfer: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchDigest {
    pub batch_id: B32,
    pub digest: B32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbortReason {
    DeadlinePassed,
    DigestMismatch,
    ImportRefused,
    Operator,
    LinkLost,
    NotWaiting,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresignAbort {
    pub batch_id: B32,
    pub reason: AbortReason,
}

// ---------------------------------------------------------------- SP6 signing -------------

/// `WithdrawalEnvelope` (DESIGN SP6 step 1), signed by UPSTREAM.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalEnvelope {
    pub request_id: B32,
    pub key_id: KeyId,
    pub chain: String,
    pub raw_tx: Bytes,
    pub inputs: u32,
    pub path: String,
    pub prod_policy_ver: u64,
    pub cold_policy_ver: u64,
    pub not_after: u64,
    /// UPSTREAM's signed time (design-notes: trusted time, DESIGN §9.3).
    pub upstream_time: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobItem {
    pub input: u32,
    pub presig_id: PresigId,
    pub ssid: B32,
}

/// `Job` (DESIGN SP6 step 3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub job_seq: u64,
    /// Encoded `SignedMsg<WithdrawalEnvelope>`, forwarded verbatim.
    pub envelope: Bytes,
    pub key_version: u32,
    pub items: Vec<JobItem>,
    /// PROD's signed time (second independent time source).
    pub prod_time: u64,
    /// HPKE to COLD of the fragments, `aad = H(Job without ciphertext)`.
    pub sealed: Sealed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Signed,
    Rejected,
    Expired,
    Fault(Fault),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub job_seq: u64,
    pub request_id: B32,
    pub outcome: Outcome,
    pub reason: String,
    pub txid: Option<B32>,
    pub signed_tx: Option<Bytes>,
}

// ---------------------------------------------------------------- SP7 control -------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreezeNotice {
    pub key_id: KeyId,
    pub key_version: u32,
    pub fault: Fault,
    pub evidence_hash: B32,
}

/// Reference policy rules. Content is the deployer's choice (DESIGN SP7 §4); this prototype
/// ships a simple reference policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PolicyRules {
    /// Max value per transaction (chain base units, as decimal string to avoid u128 in CBOR).
    pub max_per_tx: String,
    /// Max value per rolling day.
    pub max_per_day: String,
    /// Allowed destination addresses (lower-case hex for EVM).
    pub allowlist: Vec<String>,
    /// Allowed EVM chain ids.
    pub chain_ids: Vec<u64>,
    /// Allow contract calls (non-empty calldata)?
    pub allow_calldata: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundle {
    pub target: Role,
    pub key_id: KeyId,
    pub version: u64,
    pub rules: PolicyRules,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolStatus {
    pub pool: PoolId,
    pub available: Vec<PresigId>,
    pub high_water: PresigId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrphanDelete {
    pub pool: PoolId,
    pub presig_ids: Vec<PresigId>,
    /// Delete every id in blocks `< up_to_block`.
    pub up_to_block: Option<u32>,
}

// ---------------------------------------------------------------- SP9 QR ------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QrPairing {
    pub channel_id: B32,
    pub cold_cert_hash: B32,
    pub prod_cert_hash: B32,
    pub version: u64,
}

// ---------------------------------------------------------------- SP10 address book --------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressStatus {
    Active,
    Retired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressEntry {
    pub chain: String,
    pub path: String,
    pub encoding: String,
    pub address: String,
    pub status: AddressStatus,
    pub valid_from: u64,
    pub control_sig: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressBook {
    pub key_id: KeyId,
    pub key_version: u32,
    pub manifest_hash: B32,
    pub book_version: u64,
    pub entries: Vec<AddressEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressQuery {
    pub request_id: B32,
    pub chain: String,
    pub address: Option<String>,
    pub path: Option<String>,
    pub nonce: B32,
    pub not_after: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressProof {
    pub nonce: B32,
    pub entry: AddressEntry,
    /// Encoded `QuorumSignedMsg<AddressBook>`.
    pub book: Bytes,
    /// Encoded `QuorumSignedMsg<KeyManifest>`.
    pub manifest: Bytes,
    /// Encoded `QuorumSignedMsg<PartyCert>` of PROD.
    pub prod_cert: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotFound {
    pub nonce: B32,
    pub request_id: B32,
}

/// Step 6 of the frame check: decode `body` canonically as the struct registered for `t`.
pub fn validate(t: crate::MsgType, body: &[u8]) -> Result<(), crate::WireError> {
    use crate::{decode_canonical as d, MsgType as T};
    match t {
        T::LinkHello => d::<LinkHello>(body).map(drop),
        T::PartyCert => d::<PartyCert>(body).map(drop),
        T::RosterUpdate => d::<Roster>(body).map(drop),
        T::RevocationList => d::<RevocationList>(body).map(drop),
        T::CeremonyOpen => d::<CeremonyOpen>(body).map(drop),
        T::KeyManifest => d::<KeyManifest>(body).map(drop),
        T::SharePackage => d::<SharePackage>(body).map(drop),
        T::ShareReceipt => d::<ShareReceipt>(body).map(drop),
        T::Activate | T::Retire | T::Unfreeze => d::<KeyControl>(body).map(drop),
        T::CeremonyRound => d::<Bytes>(body).map(drop),
        T::WakeOpen => d::<WakeOpen>(body).map(drop),
        T::WakeAccept => d::<WakeAccept>(body).map(drop),
        T::WakeClose => d::<WakeClose>(body).map(drop),
        T::QuorumFile => d::<QuorumFile>(body).map(drop),
        T::PresignOpen => d::<PresignOpen>(body).map(drop),
        T::PresignAccept => d::<PresignAccept>(body).map(drop),
        T::PresignRefuse => d::<PresignRefuse>(body).map(drop),
        T::PresignMsg | T::FrostCommitments => d::<PresignMsg>(body).map(drop),
        T::PresignStored => d::<PresignStored>(body).map(drop),
        T::ShareMasks => d::<ShareMasks>(body).map(drop),
        T::PresigTransfer => d::<PresigTransfer>(body).map(drop),
        T::MediaBundle => d::<MediaBundle>(body).map(drop),
        T::TransferAck | T::PresignActivate => d::<BatchDigest>(body).map(drop),
        T::PresignAbort => d::<PresignAbort>(body).map(drop),
        T::WithdrawalEnvelope => d::<WithdrawalEnvelope>(body).map(drop),
        T::Job => d::<Job>(body).map(drop),
        T::Status => d::<Status>(body).map(drop),
        T::FreezeNotice => d::<FreezeNotice>(body).map(drop),
        T::PolicyBundle => d::<PolicyBundle>(body).map(drop),
        T::PoolStatus => d::<PoolStatus>(body).map(drop),
        T::OrphanDelete => d::<OrphanDelete>(body).map(drop),
        T::QrPairing => d::<QrPairing>(body).map(drop),
        T::AddressBook => d::<AddressBook>(body).map(drop),
        T::AddressQuery => d::<AddressQuery>(body).map(drop),
        T::AddressProof => d::<AddressProof>(body).map(drop),
        T::NotFound => d::<NotFound>(body).map(drop),
    }
}

/// `ShareMasks` (FROST only, DESIGN SP5 §3 step 1): δ values HPKE-sealed to COLD.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareMasks {
    pub batch_id: B32,
    pub sealed: Sealed,
}
