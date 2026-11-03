//! Shared engine pieces. Contains **no MPC code**, so PROD can depend on it.

pub mod address;
pub mod digest;
pub mod keyring;
pub mod out;
pub mod replay;

pub use out::{Event, Out};
