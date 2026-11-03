//! Chain decoders (DESIGN SP6 step 2/4: each of PROD and COLD **decodes `raw_tx` itself**).
//!
//! Prototype scope: EVM EIP-1559 (type 0x02) transactions with an empty access list.
//! Raw hashes, `personal_sign` payloads and other formats are refused (DESIGN §9.2).

pub mod evm;
pub mod rlp;

/// A decoded withdrawal, as each checker sees it from its own decode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoded {
    /// One value to sign per input (`mᵢ`). EVM: exactly one sighash.
    pub messages: Vec<[u8; 32]>,
    /// Destination address (lower-case hex, `0x…`).
    pub to: String,
    /// Value in base units.
    pub value: u128,
    /// Chain id.
    pub chain_id: u64,
    /// Calldata present?
    pub has_calldata: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChainError {
    #[error("unsupported chain {0}")]
    UnsupportedChain(String),
    #[error("malformed transaction: {0}")]
    Malformed(&'static str),
    #[error("chain id {got} does not match {want}")]
    ChainId { got: u64, want: u64 },
}

/// Decode `raw_tx` for `chain` (`"evm:<chain_id>"`).
pub fn decode(chain: &str, raw_tx: &[u8]) -> Result<Decoded, ChainError> {
    if let Some(id) = chain.strip_prefix("evm:") {
        let want: u64 = id.parse().map_err(|_| ChainError::UnsupportedChain(chain.into()))?;
        let tx = evm::Eip1559::decode_unsigned(raw_tx)?;
        if tx.chain_id != want {
            return Err(ChainError::ChainId { got: tx.chain_id, want });
        }
        return Ok(Decoded {
            messages: vec![tx.sighash()],
            to: format!("0x{}", hex::encode(tx.to)),
            value: tx.value,
            chain_id: tx.chain_id,
            has_calldata: !tx.data.is_empty(),
        });
    }
    Err(ChainError::UnsupportedChain(chain.into()))
}

/// Assemble the signed transaction and its id.
pub fn assemble(chain: &str, raw_tx: &[u8], sigs: &[([u8; 64], u8)]) -> Result<(Vec<u8>, [u8; 32]), ChainError> {
    if chain.starts_with("evm:") {
        let tx = evm::Eip1559::decode_unsigned(raw_tx)?;
        let (sig, recid) = sigs.first().ok_or(ChainError::Malformed("no signature"))?;
        let signed = tx.encode_signed(sig, recid & 1);
        let txid = chp_crypto::hash::keccak256(&signed);
        return Ok((signed, txid));
    }
    Err(ChainError::UnsupportedChain(chain.into()))
}
