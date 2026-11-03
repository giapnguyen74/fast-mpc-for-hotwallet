//! SP1 tests: handshake, 6-step frame check, matrix, quorum, rosters, revocation.

use chp_auth::{
    link::{accept_hello, make_hello, HelloParams, Link},
    matrix::may_send,
    quorum::Custodians,
    sign_msg,
    trust::{Pinned, Trust},
    AuthError,
};
use chp_crypto::ident::{key_hash, IdKey};
use chp_wire::{
    encode,
    msgs::{BatchDigest, FreezeNotice, PartyCert, PolicyBundle, PolicyRules, RevocationList, Roster},
    Fault, MsgType, QuorumRole, Role, B32,
};

const NOW: u64 = 1_000_000;

struct Fx {
    ceremony: Custodians,
    policy: Custodians,
    pinned: Pinned,
}

fn fx() -> Fx {
    let ceremony = Custodians::generate(5);
    let policy = Custodians::generate(3);
    let pinned = Pinned {
        rosters: vec![
            Roster { role: QuorumRole::Ceremony, version: 1, members: ceremony.members(), threshold: 3 },
            Roster { role: QuorumRole::PolicyProd, version: 1, members: policy.members(), threshold: 2 },
            Roster { role: QuorumRole::PolicyCold, version: 1, members: policy.members(), threshold: 2 },
        ],
        releases: vec![chp_tee::measurement_of("good")],
    };
    Fx { ceremony, policy, pinned }
}

struct Party {
    id: IdKey,
    cert: Vec<u8>,
    role: Role,
}

fn party(f: &Fx, role: Role, image: &str, not_after: u64) -> Party {
    let id = IdKey::generate(&mut rand::thread_rng());
    let c = PartyCert {
        role,
        party_index: 0,
        replica: 0,
        id_pk: B32(id.public()),
        wrap_pk: B32([9; 32]),
        measurement: chp_tee::measurement_of(image),
        key_ids: vec![],
        not_before: 0,
        not_after,
        qr_route: false,
    };
    Party { cert: f.ceremony.sign(3, MsgType::PartyCert, &c), id, role }
}

fn hello(p: &Party, nonce: u8, peer_nonce: Option<B32>, tls: B32) -> Vec<u8> {
    make_hello(HelloParams {
        id: &p.id,
        cert: &p.cert,
        roster_updates: vec![],
        nonce: B32([nonce; 32]),
        peer_nonce,
        keys: vec![],
        policy_ver: None,
        revocation_ver: 0,
        tls_binding: tls,
    })
}

/// Install a link `from → to` (the receiver's view of `from`).
fn link(f: &Fx, from: &Party, to: Role) -> Link {
    let mut t = Trust::new(&f.pinned);
    let tls = B32([7; 32]);
    let allowed: Vec<Role> = Role::ALL.to_vec();
    accept_hello(&mut t, to, NOW, &hello(from, 1, None, tls), tls, &allowed, None).unwrap().0
}

#[test]
fn handshake_cold_to_prod_succeeds_both_ways() {
    let f = fx();
    let cold = party(&f, Role::Cold, "good", NOW + 10);
    let prod = party(&f, Role::Prod, "good", NOW + 10);
    let tls = B32([3; 32]);
    let mut tp = Trust::new(&f.pinned);
    let mut tc = Trust::new(&f.pinned);
    let h1 = hello(&cold, 1, None, tls);
    let (_l, h) = accept_hello(&mut tp, Role::Prod, NOW, &h1, tls, &[Role::Cold], None).unwrap();
    let h2 = hello(&prod, 2, Some(h.nonce), tls);
    accept_hello(&mut tc, Role::Cold, NOW, &h2, tls, &[Role::Hot, Role::Prod], Some(B32([1; 32]))).unwrap();
}

#[test]
fn handshake_refusals() {
    let f = fx();
    let tls = B32([3; 32]);
    let mut t = Trust::new(&f.pinned);
    let hot = party(&f, Role::Hot, "good", NOW + 10);
    let prod = party(&f, Role::Prod, "good", NOW + 10);
    // HOT and PROD refuse each other's hellos.
    assert!(accept_hello(&mut t, Role::Prod, NOW, &hello(&hot, 1, None, tls), tls, &Role::ALL, None).is_err());
    assert!(accept_hello(&mut t, Role::Hot, NOW, &hello(&prod, 1, None, tls), tls, &Role::ALL, None).is_err());
    let cold = party(&f, Role::Cold, "good", NOW + 10);
    // relayed onto another connection
    let e = accept_hello(&mut t, Role::Prod, NOW, &hello(&cold, 1, None, tls), B32([4; 32]), &[Role::Cold], None);
    assert!(matches!(e, Err(AuthError::Handshake(_))));
    // expired certificate
    let old = party(&f, Role::Cold, "good", NOW - 1);
    assert!(matches!(
        accept_hello(&mut t, Role::Prod, NOW, &hello(&old, 1, None, tls), tls, &[Role::Cold], None),
        Err(AuthError::Cert(_))
    ));
    // measurement not on the release list
    let evil = party(&f, Role::Cold, "evil-build", NOW + 10);
    assert!(matches!(
        accept_hello(&mut t, Role::Prod, NOW, &hello(&evil, 1, None, tls), tls, &[Role::Cold], None),
        Err(AuthError::Cert(_))
    ));
    // wrong peer_nonce echo
    assert!(accept_hello(&mut t, Role::Cold, NOW, &hello(&prod, 2, Some(B32([0; 32])), tls), tls, &[Role::Prod], Some(B32([1; 32]))).is_err());
    // cert signed by too few custodians
    let id = IdKey::generate(&mut rand::thread_rng());
    let c = PartyCert {
        role: Role::Cold, party_index: 0, replica: 0, id_pk: B32(id.public()), wrap_pk: B32([0; 32]),
        measurement: chp_tee::measurement_of("good"), key_ids: vec![], not_before: 0, not_after: NOW + 10, qr_route: false,
    };
    let weak = Party { cert: f.ceremony.sign(2, MsgType::PartyCert, &c), id, role: Role::Cold };
    assert!(matches!(
        accept_hello(&mut t, Role::Prod, NOW, &hello(&weak, 1, None, tls), tls, &[Role::Cold], None),
        Err(AuthError::Quorum(_))
    ));
    let _ = weak.role;
}

fn freeze_body() -> FreezeNotice {
    FreezeNotice { key_id: B32([1; 32]), key_version: 1, fault: Fault::FinalVerify, evidence_hash: B32([2; 32]) }
}

#[test]
fn frame_check_steps_in_order_and_refusals_change_nothing() {
    let f = fx();
    let t = Trust::new(&f.pinned);
    let prod = party(&f, Role::Prod, "good", NOW + 10);
    let mut l = link(&f, &prod, Role::Cold);
    let ok1 = encode(&sign_msg(&prod.id, MsgType::FreezeNotice, 1, encode(&freeze_body())));

    // step 1: unknown type
    let mut unk = sign_msg(&prod.id, MsgType::FreezeNotice, 1, encode(&freeze_body()));
    unk.msg_type = 999;
    assert_eq!(l.check(&t, NOW, &encode(&unk)), Err(AuthError::UnknownType(999)));
    // step 2: wrong signer
    let other = IdKey::generate(&mut rand::thread_rng());
    assert_eq!(l.check(&t, NOW, &encode(&sign_msg(&other, MsgType::FreezeNotice, 1, encode(&freeze_body())))), Err(AuthError::WrongSigner));
    // step 3: gap
    let gap = encode(&sign_msg(&prod.id, MsgType::FreezeNotice, 2, encode(&freeze_body())));
    assert!(matches!(l.check(&t, NOW, &gap), Err(AuthError::BadSeq { got: 2, want: 1 })));
    // step 4: role (PROD may not send PresignActivate)
    let bd = BatchDigest { batch_id: B32([0; 32]), digest: B32([0; 32]) };
    let act = encode(&sign_msg(&prod.id, MsgType::PresignActivate, 1, encode(&bd)));
    assert!(matches!(l.check(&t, NOW, &act), Err(AuthError::RoleNotAllowed { .. })));
    // step 5: tampered body
    let mut tam = sign_msg(&prod.id, MsgType::FreezeNotice, 1, encode(&freeze_body()));
    let mut fb = freeze_body();
    fb.fault = Fault::Presign;
    tam.body = encode(&fb).into();
    assert_eq!(l.check(&t, NOW, &encode(&tam)), Err(AuthError::BadSignature));
    // step 6: body of the wrong shape (signed correctly)
    let wrong = encode(&sign_msg(&prod.id, MsgType::FreezeNotice, 1, encode(&bd)));
    assert!(matches!(l.check(&t, NOW, &wrong), Err(AuthError::Body(_))));

    // none of the refusals advanced the sequence: seq 1 is still accepted
    assert_eq!(l.check(&t, NOW, &ok1).unwrap().0, MsgType::FreezeNotice);
    // replay refused
    assert!(matches!(l.check(&t, NOW, &ok1), Err(AuthError::BadSeq { got: 1, want: 2 })));
    // streams are independent: a stream-A message starts at seq 1
    let job_like = encode(&sign_msg(&prod.id, MsgType::TransferAck, 2, encode(&bd)));
    assert_eq!(l.check(&t, NOW, &job_like).unwrap().0, MsgType::TransferAck); // stream C seq 2
}

#[test]
fn exhaustive_role_matrix_on_links() {
    // Every link message type × every sender role × the receivers of real links: the frame
    // check accepts exactly what the matrix allows (step 6 may still refuse the dummy body,
    // so we only assert that a forbidden pair is refused at step 4 or earlier).
    let f = fx();
    let t = Trust::new(&f.pinned);
    // Only these links can exist (DESIGN SP1 §4); HOT↔PROD cannot even be installed.
    for (from, to) in [(Role::Hot, Role::Prod), (Role::Prod, Role::Hot)] {
        let p = party(&f, from, "good", NOW + 10);
        let mut tr = Trust::new(&f.pinned);
        let tls = B32([7; 32]);
        assert!(accept_hello(&mut tr, to, NOW, &hello(&p, 1, None, tls), tls, &Role::ALL, None).is_err());
    }
    for (from, to) in [(Role::Cold, Role::Hot), (Role::Hot, Role::Cold), (Role::Cold, Role::Prod), (Role::Prod, Role::Cold)] {
        let p = party(&f, from, "good", NOW + 10);
        {
            for ty in MsgType::ALL.iter().copied().filter(|m| m.stream().is_some() && *m != MsgType::LinkHello) {
                let mut l = link(&f, &p, to);
                let fr = encode(&sign_msg(&p.id, ty, 1, encode(&0u8)));
                let r = l.check(&t, NOW, &fr);
                if may_send(ty, from, to) {
                    assert!(matches!(r, Err(AuthError::Body(_))), "{from:?}→{to:?} {ty:?}: {r:?}");
                } else {
                    assert!(matches!(r, Err(AuthError::RoleNotAllowed { .. })), "{from:?}→{to:?} {ty:?}: {r:?}");
                }
            }
        }
    }
}

#[test]
fn quorum_threshold_duplicates_and_non_members() {
    let f = fx();
    let t = Trust::new(&f.pinned);
    let rl = RevocationList { version: 1, revoked: vec![] };
    assert!(t.verify_quorum::<RevocationList>(&f.ceremony.sign(3, MsgType::RevocationList, &rl), MsgType::RevocationList).is_ok());
    assert!(t.verify_quorum::<RevocationList>(&f.ceremony.sign(2, MsgType::RevocationList, &rl), MsgType::RevocationList).is_err());
    // duplicated signer does not count twice
    let mut q: chp_wire::QuorumSignedMsg = chp_wire::decode_canonical(&f.ceremony.sign(2, MsgType::RevocationList, &rl)).unwrap();
    q.sigs.push(q.sigs[0].clone());
    assert!(t.verify_quorum::<RevocationList>(&encode(&q), MsgType::RevocationList).is_err());
    // non-members ignored
    let outsiders = Custodians::generate(5);
    assert!(t.verify_quorum::<RevocationList>(&outsiders.sign(5, MsgType::RevocationList, &rl), MsgType::RevocationList).is_err());
    // type confusion: a quorum-signed RevocationList is not an Unfreeze
    assert!(matches!(
        t.verify_quorum::<RevocationList>(&f.ceremony.sign(3, MsgType::RevocationList, &rl), MsgType::Unfreeze),
        Err(AuthError::WrongType { .. })
    ));
}

#[test]
fn policy_bundles_need_the_policy_quorum() {
    let f = fx();
    let t = Trust::new(&f.pinned);
    let pb = PolicyBundle { target: Role::Cold, key_id: B32([1; 32]), version: 1, rules: PolicyRules::default() };
    assert!(t.verify_quorum::<PolicyBundle>(&f.policy.sign(2, MsgType::PolicyBundle, &pb), MsgType::PolicyBundle).is_ok());
    // the ceremony quorum cannot change policy
    assert!(t.verify_quorum::<PolicyBundle>(&f.ceremony.sign(5, MsgType::PolicyBundle, &pb), MsgType::PolicyBundle).is_err());
}

#[test]
fn anti_rollback_and_revocation() {
    let f = fx();
    let mut t = Trust::new(&f.pinned);
    t.bump_version("unfreeze/k", 1).unwrap();
    assert!(matches!(t.bump_version("unfreeze/k", 1), Err(AuthError::Rollback { .. })));
    t.bump_version("unfreeze/k", 5).unwrap();
    assert!(t.bump_version("unfreeze/k", 4).is_err());

    let prod = party(&f, Role::Prod, "good", NOW + 10);
    let mut l = link(&f, &prod, Role::Cold);
    let h = B32(key_hash(&prod.id.public()));
    let rl2 = f.ceremony.sign(3, MsgType::RevocationList, &RevocationList { version: 2, revoked: vec![h] });
    assert_eq!(t.apply_revocation(&rl2).unwrap(), vec![h]);
    // old list cannot be replayed
    let rl1 = f.ceremony.sign(3, MsgType::RevocationList, &RevocationList { version: 1, revoked: vec![] });
    assert!(matches!(t.apply_revocation(&rl1), Err(AuthError::Rollback { .. })));
    // frames from the revoked party are refused; its cert no longer verifies
    let fr = encode(&sign_msg(&prod.id, MsgType::FreezeNotice, 1, encode(&freeze_body())));
    assert_eq!(l.check(&t, NOW, &fr), Err(AuthError::Revoked));
    assert_eq!(t.verify_cert(&prod.cert, NOW).unwrap_err(), AuthError::Revoked);
}

#[test]
fn roster_rotation_without_release() {
    let f = fx();
    let mut t = Trust::new(&f.pinned);
    let new = Custodians::generate(4);
    let upd = Roster { role: QuorumRole::Ceremony, version: 2, members: new.members(), threshold: 3 };
    // signed by the *current* roster
    let ru = f.ceremony.sign(3, MsgType::RosterUpdate, &upd);
    assert!(t.apply_roster_update(&ru).unwrap());
    // old custodians lose power, new ones gain it
    let rl = RevocationList { version: 1, revoked: vec![] };
    assert!(t.verify_quorum::<RevocationList>(&f.ceremony.sign(5, MsgType::RevocationList, &rl), MsgType::RevocationList).is_err());
    assert!(t.verify_quorum::<RevocationList>(&new.sign(3, MsgType::RevocationList, &rl), MsgType::RevocationList).is_ok());
    // an update signed by outsiders is refused
    let evil = Custodians::generate(4);
    let upd3 = Roster { role: QuorumRole::Ceremony, version: 3, members: evil.members(), threshold: 1 };
    assert!(t.apply_roster_update(&evil.sign(4, MsgType::RosterUpdate, &upd3)).is_err());
}

#[test]
fn revoked_custodians_do_not_count_towards_a_quorum() {
    let f = fx();
    let mut t = Trust::new(&f.pinned);
    // revoke custodian #0 (signed by #1..#3)
    let c0 = B32(key_hash(&f.ceremony.0[0].public()));
    let rl = RevocationList { version: 1, revoked: vec![c0] };
    let q: chp_wire::QuorumSignedMsg = chp_wire::decode_canonical(&f.ceremony.sign(5, MsgType::RevocationList, &rl)).unwrap();
    t.apply_revocation(&encode(&q)).unwrap();
    // #0 + #1 + #2 sign: only two count now → refused
    let rl2 = RevocationList { version: 2, revoked: vec![] };
    let three = f.ceremony.sign(3, MsgType::RevocationList, &rl2);
    assert!(t.verify_quorum::<RevocationList>(&three, MsgType::RevocationList).is_err());
    assert!(t.verify_quorum::<RevocationList>(&f.ceremony.sign(4, MsgType::RevocationList, &rl2), MsgType::RevocationList).is_ok());
}

#[test]
fn an_expired_peer_certificate_stops_an_installed_link() {
    let f = fx();
    let t = Trust::new(&f.pinned);
    let prod = party(&f, Role::Prod, "good", NOW + 10);
    let mut l = link(&f, &prod, Role::Cold);
    let fr = encode(&sign_msg(&prod.id, MsgType::FreezeNotice, 1, encode(&freeze_body())));
    assert!(matches!(l.check(&t, NOW + 11, &fr), Err(AuthError::Cert(_))));
    assert!(l.check(&t, NOW, &fr).is_ok());
}
