//! Shared types: byte newtypes, roles, ids.

use serde::{Deserialize, Serialize};

/// 32 bytes, encoded as a CBOR byte string.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct B32(#[serde(with = "serde_bytes")] pub [u8; 32]);

/// 64 bytes (signatures), encoded as a CBOR byte string.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct B64(#[serde(with = "serde_bytes")] pub [u8; 64]);

/// Variable-length bytes, encoded as a CBOR byte string.
#[derive(Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct Bytes(#[serde(with = "serde_bytes")] pub Vec<u8>);

macro_rules! hexdbg {
    ($t:ty) => {
        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let b: &[u8] = &self.0;
                if b.len() > 12 {
                    write!(f, "{}…", hex::encode(&b[..8]))
                } else {
                    write!(f, "{}", hex::encode(b))
                }
            }
        }
    };
}
hexdbg!(B32);
hexdbg!(B64);
hexdbg!(Bytes);

impl From<[u8; 32]> for B32 {
    fn from(v: [u8; 32]) -> Self {
        B32(v)
    }
}
impl From<Vec<u8>> for Bytes {
    fn from(v: Vec<u8>) -> Self {
        Bytes(v)
    }
}

/// Party roles (DESIGN SP1 §3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Role {
    Hot,
    Cold,
    Prod,
    Rec,
    Upstream,
    Requester,
}

impl Role {
    pub const ALL: [Role; 6] = [Role::Hot, Role::Cold, Role::Prod, Role::Rec, Role::Upstream, Role::Requester];
}

/// Quorum roles (DESIGN SP1 §2; `Incident` / `Revocation` / per-source policy only with
/// quorum separation, otherwise the ceremony quorum signs those objects).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, PartialOrd, Ord)]
pub enum QuorumRole {
    Ceremony,
    Incident,
    Revocation,
    /// Policy quorum for PROD's policy source.
    PolicyProd,
    /// Policy quorum for COLD's policy source.
    PolicyCold,
}

/// Signing protocol of a key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum Protocol {
    Dkls23Secp256k1,
    FrostEd25519,
    FrostTaproot,
}

pub type KeyId = B32;
pub type PresigId = u64;

/// Key lifecycle (DESIGN SP3 §3; forward-only except Frozen ⇄ Active via quorum `Unfreeze`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum KeyState {
    ActivePending,
    Active,
    Retired,
}

/// Freeze / fault codes (DESIGN SP6 §6, SP7 §3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum Fault {
    ProdFragment,
    FinalVerify,
    PresigState,
    Presign,
}

/// Pool identity `(key_id, key_version, path)` (DESIGN SP4 §4 step 1).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, PartialOrd, Ord)]
pub struct PoolId {
    pub key_id: KeyId,
    pub key_version: u32,
    pub path: String,
}

/// Presignature id layout `hot_replica ‖ cold_replica ‖ block ‖ index` (DESIGN SP4 §4 step 1):
/// 8 bits HOT replica, 8 bits COLD replica, 32 bits block, 16 bits index.
pub mod presig_id {
    use super::PresigId;
    pub fn make(hot_replica: u8, cold_replica: u8, block: u32, index: u16) -> PresigId {
        ((hot_replica as u64) << 56) | ((cold_replica as u64) << 48) | ((block as u64) << 16) | index as u64
    }
    pub fn block(id: PresigId) -> u32 {
        ((id >> 16) & 0xffff_ffff) as u32
    }
    pub fn index(id: PresigId) -> u16 {
        (id & 0xffff) as u16
    }
    pub fn replicas(id: PresigId) -> (u8, u8) {
        ((id >> 56) as u8, (id >> 48) as u8)
    }
}
