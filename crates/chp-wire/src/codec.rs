//! Deterministic CBOR (DESIGN SP1 §5 step 6).
//!
//! Encoding: `ciborium` with serde; structs encode as maps with fields in declaration order,
//! integers minimally. A body is accepted only if decoding it and re-encoding yields the same
//! bytes, which rejects unknown fields, trailing bytes, duplicate keys, reordered keys,
//! indefinite lengths and non-minimal integers.

use serde::{de::DeserializeOwned, Serialize};

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum WireError {
    #[error("CBOR decode failed")]
    Decode,
    #[error("body is not canonical")]
    NotCanonical,
    #[error("frame too large")]
    TooLarge,
}

/// Hard cap on any encoded frame or body (DESIGN §6.1 "hard size limits").
pub const MAX_FRAME_BYTES: usize = 1 << 20;

pub fn encode<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).expect("CBOR encoding into Vec cannot fail");
    out
}

pub fn decode_canonical<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, WireError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(WireError::TooLarge);
    }
    let v: T = ciborium::from_reader(bytes).map_err(|_| WireError::Decode)?;
    if encode(&v) != bytes {
        return Err(WireError::NotCanonical);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct T {
        a: u64,
        b: String,
    }

    #[test]
    fn roundtrip() {
        let t = T { a: 5, b: "x".into() };
        assert_eq!(decode_canonical::<T>(&encode(&t)).unwrap(), t);
    }

    #[test]
    fn trailing_bytes_refused() {
        let mut b = encode(&T { a: 5, b: "x".into() });
        b.push(0);
        assert!(decode_canonical::<T>(&b).is_err());
    }

    #[test]
    fn unknown_field_refused() {
        #[derive(Serialize)]
        struct U {
            a: u64,
            b: String,
            c: u8,
        }
        let b = encode(&U { a: 5, b: "x".into(), c: 1 });
        assert_eq!(decode_canonical::<T>(&b), Err(WireError::NotCanonical));
    }

    #[test]
    fn non_minimal_integer_refused() {
        // map(2) "a" -> uint8-encoded 5 (0x18 0x05 instead of 0x05), "b" -> "x"
        let b = [0xa2, 0x61, b'a', 0x18, 0x05, 0x61, b'b', 0x61, b'x'];
        assert_eq!(decode_canonical::<T>(&b), Err(WireError::NotCanonical));
    }

    #[test]
    fn reordered_keys_refused() {
        let b = [0xa2, 0x61, b'b', 0x61, b'x', 0x61, b'a', 0x05];
        assert_eq!(decode_canonical::<T>(&b), Err(WireError::NotCanonical));
    }
}
