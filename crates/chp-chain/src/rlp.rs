//! Minimal RLP (Ethereum yellow paper, appendix B), strict: canonical lengths only.

use crate::ChainError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    Bytes(Vec<u8>),
    List(Vec<Item>),
}

const M: ChainError = ChainError::Malformed("rlp");

fn be_len(b: &[u8]) -> Result<usize, ChainError> {
    if b.is_empty() || b[0] == 0 || b.len() > 8 {
        return Err(M);
    }
    Ok(b.iter().fold(0usize, |a, x| (a << 8) | *x as usize))
}

/// Max list nesting (EIP-1559 needs 2). Untrusted input must not recurse without bound
/// (security review round 2: deep nesting overflowed the stack and aborted the process).
pub const MAX_DEPTH: usize = 8;

fn decode_one(b: &[u8], depth: usize) -> Result<(Item, usize), ChainError> {
    if depth > MAX_DEPTH {
        return Err(ChainError::Malformed("rlp nesting too deep"));
    }
    let p = *b.first().ok_or(M)?;
    match p {
        0x00..=0x7f => Ok((Item::Bytes(vec![p]), 1)),
        0x80..=0xb7 => {
            let l = (p - 0x80) as usize;
            let d = b.get(1..1 + l).ok_or(M)?;
            if l == 1 && d[0] < 0x80 {
                return Err(M); // non-canonical single byte
            }
            Ok((Item::Bytes(d.to_vec()), 1 + l))
        }
        0xb8..=0xbf => {
            let ll = (p - 0xb7) as usize;
            let l = be_len(b.get(1..1 + ll).ok_or(M)?)?;
            if l < 56 {
                return Err(M);
            }
            Ok((Item::Bytes(b.get(1 + ll..1 + ll + l).ok_or(M)?.to_vec()), 1 + ll + l))
        }
        0xc0..=0xf7 => {
            let l = (p - 0xc0) as usize;
            Ok((Item::List(decode_list(b.get(1..1 + l).ok_or(M)?, depth + 1)?), 1 + l))
        }
        0xf8..=0xff => {
            let ll = (p - 0xf7) as usize;
            let l = be_len(b.get(1..1 + ll).ok_or(M)?)?;
            if l < 56 {
                return Err(M);
            }
            Ok((Item::List(decode_list(b.get(1 + ll..1 + ll + l).ok_or(M)?, depth + 1)?), 1 + ll + l))
        }
    }
}

fn decode_list(mut b: &[u8], depth: usize) -> Result<Vec<Item>, ChainError> {
    let mut v = Vec::new();
    while !b.is_empty() {
        let (it, n) = decode_one(b, depth)?;
        v.push(it);
        b = &b[n..];
    }
    Ok(v)
}

/// Decode exactly one item spanning all of `b`.
pub fn decode(b: &[u8]) -> Result<Item, ChainError> {
    let (it, n) = decode_one(b, 0)?;
    if n != b.len() {
        return Err(M);
    }
    Ok(it)
}

fn len_prefix(base: u8, l: usize, out: &mut Vec<u8>) {
    if l < 56 {
        out.push(base + l as u8);
    } else {
        let lb: Vec<u8> = l.to_be_bytes().iter().copied().skip_while(|x| *x == 0).collect();
        out.push(base + 55 + lb.len() as u8);
        out.extend(lb);
    }
}

pub fn encode(it: &Item) -> Vec<u8> {
    let mut out = Vec::new();
    match it {
        Item::Bytes(d) if d.len() == 1 && d[0] < 0x80 => out.push(d[0]),
        Item::Bytes(d) => {
            len_prefix(0x80, d.len(), &mut out);
            out.extend(d);
        }
        Item::List(xs) => {
            let body: Vec<u8> = xs.iter().flat_map(encode).collect();
            len_prefix(0xc0, body.len(), &mut out);
            out.extend(body);
        }
    }
    out
}

/// Big-endian minimal integer bytes.
pub fn uint(v: u128) -> Item {
    Item::Bytes(v.to_be_bytes().iter().copied().skip_while(|x| *x == 0).collect())
}

pub fn as_uint(it: &Item) -> Result<u128, ChainError> {
    match it {
        Item::Bytes(b) if b.len() <= 16 && b.first() != Some(&0) => Ok(b.iter().fold(0u128, |a, x| (a << 8) | *x as u128)),
        _ => Err(ChainError::Malformed("integer")),
    }
}

pub fn as_bytes(it: &Item) -> Result<&[u8], ChainError> {
    match it {
        Item::Bytes(b) => Ok(b),
        _ => Err(ChainError::Malformed("bytes")),
    }
}
