//! CHP wire format (DESIGN SP1 §5–§7).
//!
//! * [`codec`]  — deterministic CBOR with a re-encode check (no unknown fields, no trailing
//!   bytes, no non-minimal integers: anything that does not re-encode to the same
//!   bytes is refused).
//! * [`types`]  — roles, ids and small shared types.
//! * [`msgs`]   — every message body in the closed registry.
//! * [`frame`]  — `SignedMsg`, `QuorumSignedMsg`, the registry [`MsgType`] and its streams.

pub mod codec;
pub mod frame;
pub mod msgs;
pub mod types;

pub use codec::{decode_canonical, encode, WireError};
pub use frame::{MsgType, QSig, QuorumSignedMsg, SignedMsg, Stream};
pub use types::*;
