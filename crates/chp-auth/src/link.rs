//! Authenticated links: `LinkHello` handshake (SP1 §4) and the 6-step frame check (SP1 §5).

use chp_crypto::ident::{self, IdKey};
use chp_wire::{
    decode_canonical, encode,
    msgs::{self, LinkHello, PartyCert},
    MsgType, Role, SignedMsg, Stream, B32,
};
use serde::Serialize;

use crate::{matrix::may_send, sign_msg, signed_msg_input, trust::Trust, AuthError, Result};

/// An installed link to one peer.
#[derive(Clone, Debug)]
pub struct Link {
    pub me: Role,
    pub peer: PartyCert,
    pub peer_signer: B32,
    pub tls_binding: B32,
    recv: [u64; 4],
    send: [u64; 4],
}

impl Link {
    fn new(me: Role, peer: PartyCert, tls_binding: B32) -> Self {
        let peer_signer = B32(ident::key_hash(&peer.id_pk.0));
        Link { me, peer, peer_signer, tls_binding, recv: [0; 4], send: [0; 4] }
    }

    /// Build the next signed frame of type `t` on this link.
    pub fn seal<T: Serialize>(&mut self, id: &IdKey, t: MsgType, body: &T) -> Vec<u8> {
        let s = t.stream().expect("link message").index();
        self.send[s] += 1;
        encode(&sign_msg(id, t, self.send[s], encode(body)))
    }

    /// The 6 checks of SP1 §5, in order, **before advancing any state**. On success the
    /// stream's sequence advances and the (type, canonical body bytes) are returned.
    pub fn check(&mut self, trust: &Trust, bytes: &[u8]) -> Result<(MsgType, Vec<u8>)> {
        let f: SignedMsg = decode_canonical(bytes).map_err(AuthError::Frame)?;
        // 1. type in the closed registry
        let t = MsgType::from_code(f.msg_type).ok_or(AuthError::UnknownType(f.msg_type))?;
        let stream = t.stream().ok_or(AuthError::RoleNotAllowed { role: self.peer.role, t, to: self.me })?;
        if stream == Stream::Hello {
            return Err(AuthError::Handshake("hello on an installed link".into()));
        }
        // 2. signer is the linked peer, valid and unrevoked
        if f.signer != self.peer_signer {
            return Err(AuthError::WrongSigner);
        }
        if trust.is_revoked(&self.peer_signer) {
            return Err(AuthError::Revoked);
        }
        // 3. seq == last + 1 on this stream
        let want = self.recv[stream.index()] + 1;
        if f.seq != want {
            return Err(AuthError::BadSeq { got: f.seq, want });
        }
        // 4. the signer's role may send this type to me
        if !may_send(t, self.peer.role, self.me) {
            return Err(AuthError::RoleNotAllowed { role: self.peer.role, t, to: self.me });
        }
        // 5. signature
        ident::verify(&self.peer.id_pk.0, &signed_msg_input(f.msg_type, f.seq, &f.body.0), &f.sig.0)
            .map_err(|_| AuthError::BadSignature)?;
        // 6. canonical body
        msgs::validate(t, &f.body.0).map_err(AuthError::Body)?;
        self.recv[stream.index()] = f.seq;
        Ok((t, f.body.0))
    }
}

/// Verify a standalone `SignedMsg` (API requests, media transfers, receipts): type, signer
/// matches `cert`, sender role allowed towards `me`, signature, canonical body. `seq` is
/// checked by the caller where relevant (media: 0; API: replay cache instead).
pub fn check_standalone(cert: &PartyCert, me: Role, bytes: &[u8], want: MsgType) -> Result<(u64, Vec<u8>)> {
    let f: SignedMsg = decode_canonical(bytes).map_err(AuthError::Frame)?;
    let t = MsgType::from_code(f.msg_type).ok_or(AuthError::UnknownType(f.msg_type))?;
    if t != want {
        return Err(AuthError::WrongType { want, got: t });
    }
    if f.signer.0 != ident::key_hash(&cert.id_pk.0) {
        return Err(AuthError::WrongSigner);
    }
    if !may_send(t, cert.role, me) {
        return Err(AuthError::RoleNotAllowed { role: cert.role, t, to: me });
    }
    ident::verify(&cert.id_pk.0, &signed_msg_input(f.msg_type, f.seq, &f.body.0), &f.sig.0)
        .map_err(|_| AuthError::BadSignature)?;
    msgs::validate(t, &f.body.0).map_err(AuthError::Body)?;
    Ok((f.seq, f.body.0))
}

/// Signer hash of a standalone frame without verifying it (to look up the certificate).
pub fn signer_of(bytes: &[u8]) -> Result<B32> {
    let f: SignedMsg = decode_canonical(bytes).map_err(AuthError::Frame)?;
    Ok(f.signer)
}

/// Parameters of a hello.
pub struct HelloParams<'a> {
    pub id: &'a IdKey,
    pub cert: &'a [u8],
    pub roster_updates: Vec<Vec<u8>>,
    pub nonce: B32,
    pub peer_nonce: Option<B32>,
    pub keys: Vec<(B32, u32)>,
    pub policy_ver: Option<u64>,
    pub revocation_ver: u64,
    pub tls_binding: B32,
}

pub fn make_hello(p: HelloParams<'_>) -> Vec<u8> {
    let h = LinkHello {
        cert: p.cert.to_vec().into(),
        roster_updates: p.roster_updates.into_iter().map(Into::into).collect(),
        nonce: p.nonce,
        peer_nonce: p.peer_nonce,
        keys: p.keys,
        policy_ver: p.policy_ver,
        revocation_ver: p.revocation_ver,
        tls_binding: p.tls_binding,
    };
    encode(&sign_msg(p.id, MsgType::LinkHello, 0, encode(&h)))
}

/// Verify a peer's hello (SP1 §4) and install the link.
///
/// * applies the peer's `RosterUpdate` chain first;
/// * certificate: roster, validity, release list, not revoked, role in `allowed_peers`;
/// * signer = H(cert.id_pk), seq 0, signature, canonical body;
/// * `tls_binding` equals this connection's exporter;
/// * for the responder's hello, `peer_nonce` echoes our nonce.
pub fn accept_hello(
    trust: &mut Trust,
    me: Role,
    now: u64,
    bytes: &[u8],
    my_tls_binding: B32,
    allowed_peers: &[Role],
    expect_peer_nonce: Option<B32>,
) -> Result<(Link, LinkHello)> {
    let f: SignedMsg = decode_canonical(bytes).map_err(AuthError::Frame)?;
    if f.msg_type != MsgType::LinkHello.code() || f.seq != 0 {
        return Err(AuthError::Handshake("not a seq-0 LinkHello".into()));
    }
    let h: LinkHello = decode_canonical(&f.body.0).map_err(AuthError::Body)?;
    for ru in &h.roster_updates {
        trust.apply_roster_update(&ru.0)?;
    }
    let (cert, _) = trust.verify_cert(&h.cert.0, now)?;
    if !allowed_peers.contains(&cert.role) || !may_send(MsgType::LinkHello, cert.role, me) {
        return Err(AuthError::Handshake(format!("peer role {:?} not allowed", cert.role)));
    }
    if f.signer.0 != ident::key_hash(&cert.id_pk.0) {
        return Err(AuthError::WrongSigner);
    }
    ident::verify(&cert.id_pk.0, &signed_msg_input(f.msg_type, 0, &f.body.0), &f.sig.0)
        .map_err(|_| AuthError::BadSignature)?;
    if h.tls_binding != my_tls_binding {
        return Err(AuthError::Handshake("tls_binding mismatch (relayed hello)".into()));
    }
    if let Some(n) = expect_peer_nonce {
        if h.peer_nonce != Some(n) {
            return Err(AuthError::Handshake("peer_nonce mismatch".into()));
        }
    }
    Ok((Link::new(me, cert, my_tls_binding), h))
}
