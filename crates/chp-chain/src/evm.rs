//! EVM EIP-1559 transactions (type 0x02).

use crate::{
    rlp::{self, as_bytes, as_uint, uint, Item},
    ChainError,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eip1559 {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee: u128,
    pub max_fee: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
}

impl Eip1559 {
    fn fields(&self) -> Vec<Item> {
        vec![
            uint(self.chain_id as u128),
            uint(self.nonce as u128),
            uint(self.max_priority_fee),
            uint(self.max_fee),
            uint(self.gas_limit as u128),
            Item::Bytes(self.to.to_vec()),
            uint(self.value),
            Item::Bytes(self.data.clone()),
            Item::List(vec![]),
        ]
    }

    /// Unsigned encoding `0x02 ‖ rlp([fields])` (what UPSTREAM sends as `raw_tx`).
    pub fn encode_unsigned(&self) -> Vec<u8> {
        let mut v = vec![0x02];
        v.extend(rlp::encode(&Item::List(self.fields())));
        v
    }

    /// Sighash `keccak256(0x02 ‖ rlp([fields]))`.
    pub fn sighash(&self) -> [u8; 32] {
        chp_crypto::hash::keccak256(&self.encode_unsigned())
    }

    /// Strict decode: type 0x02, 9 fields, 20-byte `to` (no contract creation), empty access
    /// list, and the bytes must re-encode identically.
    pub fn decode_unsigned(raw: &[u8]) -> Result<Self, ChainError> {
        let (&ty, rest) = raw.split_first().ok_or(ChainError::Malformed("empty"))?;
        if ty != 0x02 {
            return Err(ChainError::Malformed("only EIP-1559 (type 2) transactions are accepted"));
        }
        let Item::List(f) = rlp::decode(rest)? else { return Err(ChainError::Malformed("not a list")) };
        if f.len() != 9 {
            return Err(ChainError::Malformed("field count"));
        }
        let to: [u8; 20] = as_bytes(&f[5])?.try_into().map_err(|_| ChainError::Malformed("to must be 20 bytes"))?;
        if f[8] != Item::List(vec![]) {
            return Err(ChainError::Malformed("access lists are not accepted"));
        }
        let small = |i: usize| -> Result<u64, ChainError> {
            u64::try_from(as_uint(&f[i])?).map_err(|_| ChainError::Malformed("u64 overflow"))
        };
        let tx = Eip1559 {
            chain_id: small(0)?,
            nonce: small(1)?,
            max_priority_fee: as_uint(&f[2])?,
            max_fee: as_uint(&f[3])?,
            gas_limit: small(4)?,
            to,
            value: as_uint(&f[6])?,
            data: as_bytes(&f[7])?.to_vec(),
        };
        if tx.encode_unsigned() != raw {
            return Err(ChainError::Malformed("non-canonical encoding"));
        }
        Ok(tx)
    }

    /// Signed encoding `0x02 ‖ rlp([fields, y_parity, r, s])`.
    pub fn encode_signed(&self, sig: &[u8; 64], y_parity: u8) -> Vec<u8> {
        let mut f = self.fields();
        f.push(uint(y_parity as u128));
        let strip = |b: &[u8]| Item::Bytes(b.iter().copied().skip_while(|x| *x == 0).collect());
        f.push(strip(&sig[..32]));
        f.push(strip(&sig[32..]));
        let mut v = vec![0x02];
        v.extend(rlp::encode(&Item::List(f)));
        v
    }
}

/// EVM address of an uncompressed public key: last 20 bytes of Keccak-256 of `X ‖ Y`.
pub fn address_of(uncompressed65: &[u8; 65]) -> [u8; 20] {
    let h = chp_crypto::hash::keccak256(&uncompressed65[1..]);
    h[12..].try_into().expect("20 bytes")
}

/// EVM address of a secp256k1 point.
pub fn address_of_point(p: &k256::ProjectivePoint) -> String {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let enc = p.to_affine().to_encoded_point(false);
    let b: [u8; 65] = enc.as_bytes().try_into().expect("65 bytes");
    format!("0x{}", hex::encode(address_of(&b)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx() -> Eip1559 {
        Eip1559 { chain_id: 31337, nonce: 7, max_priority_fee: 1_000_000_000, max_fee: 30_000_000_000, gas_limit: 21000, to: [0x11; 20], value: 10u128.pow(18), data: vec![] }
    }

    #[test]
    fn roundtrip_and_strictness() {
        let raw = tx().encode_unsigned();
        assert_eq!(Eip1559::decode_unsigned(&raw).unwrap(), tx());
        // legacy / other types refused
        let mut legacy = raw.clone();
        legacy[0] = 0x01;
        assert!(Eip1559::decode_unsigned(&legacy).is_err());
        // trailing byte refused
        let mut t = raw.clone();
        t.push(0);
        assert!(Eip1559::decode_unsigned(&t).is_err());
        // contract creation (empty `to`) refused
        let mut f = tx().fields();
        f[5] = Item::Bytes(vec![]);
        let mut c = vec![0x02];
        c.extend(rlp::encode(&Item::List(f)));
        assert!(Eip1559::decode_unsigned(&c).is_err());
    }

    #[test]
    fn known_address_vector() {
        // private key 1 → address 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf
        let p = k256::ProjectivePoint::GENERATOR;
        assert_eq!(address_of_point(&p), "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
    }

    #[test]
    fn rlp_known_vectors() {
        assert_eq!(rlp::encode(&Item::Bytes(b"dog".to_vec())), vec![0x83, b'd', b'o', b'g']);
        assert_eq!(rlp::encode(&Item::List(vec![])), vec![0xc0]);
        assert_eq!(rlp::encode(&uint(0)), vec![0x80]);
        assert_eq!(rlp::encode(&uint(1024)), vec![0x82, 0x04, 0x00]);
        // non-canonical single byte refused
        assert!(rlp::decode(&[0x81, 0x05]).is_err());
    }
}
