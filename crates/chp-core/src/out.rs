//! Engine outputs. Engines are sans-I/O: they return what to send; the host moves bytes.

use chp_wire::{Fault, KeyId, Role, B32};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Out {
    /// A frame for a linked peer (or API caller) with this role.
    Send { to: Role, bytes: Vec<u8> },
    /// A media bundle for the operator to carry (HOT → PROD).
    Media(Vec<u8>),
    /// A signed transaction for PROD to broadcast.
    Broadcast { chain: String, signed_tx: Vec<u8>, txid: B32 },
    /// Something to show an operator (digests to compare, counters).
    Display(String),
}

/// Audit events (DESIGN §10.2). Every accepted frame, refusal, freeze, window and batch change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Refused { what: String, why: String },
    Frozen { key_id: KeyId, fault: Fault },
    Unfrozen { key_id: KeyId },
    BatchState { batch_id: B32, state: String },
    PoolDiscarded { path: String, reason: String },
    Signed { request_id: B32, txid: B32 },
    Info(String),
}
