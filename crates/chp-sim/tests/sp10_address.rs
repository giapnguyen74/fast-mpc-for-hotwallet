//! SP10 address book and address proofs, verified offline against the pinned roster only.

use chp_auth::{sign_body, trust::Trust};
use chp_core::address::{verify_proof, Asked, ProofError};
use chp_sim::*;
use chp_wire::{decode_canonical, msgs::*, Bytes, MsgType, SignedMsg, B32};

fn query<'a>(w: &World, address: Option<&'a str>, path: Option<&'a str>) -> (Asked<'a>, Vec<u8>) {
    let nonce = B32(rand::random());
    let request_id = B32(rand::random());
    let q = AddressQuery { request_id, chain: CHAIN.into(), address: address.map(Into::into), path: path.map(Into::into), nonce, not_after: w.now + 60 };
    (Asked { request_id, nonce, chain: CHAIN, address, path }, sign_body(&w.requester, MsgType::AddressQuery, 0, &q))
}

#[tokio::test(flavor = "multi_thread")]
async fn proofs_verify_offline_and_foreign_addresses_alarm() {
    let mut w = World::setup(Options::default()).await;
    // the requester holds only the pinned roster
    let verifier = Trust::new(&w.q.pinned());
    let (asked, q) = query(&w, None, Some(PATH));
    let proof = w.prod.address_query(&q, w.now).unwrap();
    let entry = verify_proof(&verifier, &proof, &asked, 0, w.now).expect("valid proof");
    assert_eq!(entry.path, PATH);
    let nonce = asked.nonce;

    // wrong nonce (a replayed answer)
    let other = Asked { nonce: B32([0; 32]), ..asked };
    assert_eq!(verify_proof(&verifier, &proof, &other, 0, w.now).unwrap_err(), ProofError::ProdSig);
    let asked = Asked { nonce, ..other };

    // Security review: asked about an attacker's address X, a compromised PROD answers with a
    // *valid* proof for a genuine address Y. The proof must answer the question asked.
    let x = "0x6666666666666666666666666666666666666666";
    let asked_x = Asked { address: Some(x), path: None, ..asked };
    assert_eq!(verify_proof(&verifier, &proof, &asked_x, 0, w.now).unwrap_err(), ProofError::WrongEntry);

    // a compromised PROD substitutes an address: the entry is no longer in the quorum-signed book
    let f: SignedMsg = decode_canonical(&proof).unwrap();
    let mut p: AddressProof = decode_canonical(&f.body.0).unwrap();
    p.entry.address = "0x6666666666666666666666666666666666666666".into();
    let forged = sign_body(&w.prod.enclave.id, MsgType::AddressProof, 0, &p);
    let asked_forged = Asked { address: Some("0x6666666666666666666666666666666666666666"), path: None, ..asked };
    assert_eq!(verify_proof(&verifier, &forged, &asked_forged, 0, w.now).unwrap_err(), ProofError::NotInBook);

    // even a book signed by a fake quorum fails at step 1
    let fake = chp_auth::quorum::Custodians::generate(5);
    let mut book: AddressBook = verifier.verify_quorum(&p.book.0, MsgType::AddressBook).unwrap();
    book.entries[0].address = "0x6666666666666666666666666666666666666666".into();
    p.book = Bytes(fake.sign(5, MsgType::AddressBook, &book));
    p.entry = book.entries[0].clone();
    let forged = sign_body(&w.prod.enclave.id, MsgType::AddressProof, 0, &p);
    assert!(matches!(verify_proof(&verifier, &forged, &asked_forged, 0, w.now), Err(ProofError::Quorum(_))));
    let _ = nonce;

    // unknown address: signed NotFound, never "probably ours"
    let (_, q) = query(&w, Some("0x2222222222222222222222222222222222222222"), None);
    let nf = w.prod.address_query(&q, w.now).unwrap();
    let f: SignedMsg = decode_canonical(&nf).unwrap();
    assert_eq!(f.msg_type, MsgType::NotFound.code());

    // replayed query nonce is refused
    assert!(w.prod.address_query(&q, w.now).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_old_book_is_an_alarm_after_a_newer_one_was_seen() {
    let mut w = World::setup(Options::default()).await;
    let verifier = Trust::new(&w.q.pinned());
    let (asked, q) = query(&w, None, Some(PATH));
    let proof = w.prod.address_query(&q, w.now).unwrap();
    // the requester has already accepted book_version 2 elsewhere
    assert!(matches!(verify_proof(&verifier, &proof, &asked, 2, w.now), Err(ProofError::OldBook { got: 1, last: 2 })));
    w.advance(1);
}

#[tokio::test(flavor = "multi_thread")]
async fn control_signature_is_by_the_derived_key_itself() {
    let w = World::setup(Options::default()).await;
    let verifier = Trust::new(&w.q.pinned());
    let book: AddressBook = verifier.verify_quorum(&w.book, MsgType::AddressBook).unwrap();
    let m: KeyManifest = verifier.verify_quorum(&w.manifest, MsgType::KeyManifest).unwrap();
    for e in &book.entries {
        assert!(chp_core::address::verify_control_sig(&m, e));
        assert_eq!(chp_core::address::derive_address(&m, &e.path).as_deref(), Some(e.address.as_str()));
        // the control signature does not verify for another path's key
        let mut other = e.clone();
        other.path = "m/other".into();
        assert!(!chp_core::address::verify_control_sig(&m, &other));
    }
}
