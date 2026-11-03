//! Role separation (DESIGN §3, rule 6): no live path into key management.

use chp_sim::*;
use chp_wire::{msgs::*, Bytes, MsgType, B32};

#[tokio::test(flavor = "multi_thread")]
async fn no_runtime_party_accepts_key_material() {
    let mut w = World::setup(Options::default()).await;
    let dkg = w.dkg.take().unwrap();
    // PROD refuses any SharePackage, even quorum-signed
    assert!(w.prod.apply_quorum(&dkg.hot_package, w.now).is_err());
    // COLD refuses key material on its runtime path
    assert!(w.cold.apply_quorum(&dkg.cold_package, w.now).is_err());
    // HOT and COLD import packages only in a quorum-opened ceremony
    assert!(w.hot.import_share(&dkg.manifest, &dkg.hot_package).is_err());
    assert!(w.cold.import_share(&dkg.manifest, &dkg.cold_package).is_err());
    // a replayed CeremonyOpen is refused (boot counter already advanced)
    assert!(w.hot.ceremony_boot(&dkg.open, w.now).is_err());
    assert!(w.cold.ceremony_boot(&dkg.open, w.now).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn hot_and_prod_cannot_link() {
    let mut w = World::setup(Options::default()).await;
    // PROD has no API to dial anybody; a hello from HOT's identity is refused by PROD.
    let tls = B32([5; 32]);
    let hello = chp_auth::link::make_hello(chp_auth::link::HelloParams {
        id: &w.hot.enclave.id,
        cert: w.hot.cert(),
        roster_updates: vec![],
        nonce: B32([1; 32]),
        peer_nonce: None,
        keys: vec![],
        policy_ver: None,
        revocation_ver: 0,
        tls_binding: tls,
    });
    assert!(w.prod.on_hello(&hello, tls, w.now).is_err());
    let hello_p = chp_auth::link::make_hello(chp_auth::link::HelloParams {
        id: &w.prod.enclave.id,
        cert: w.prod.cert(),
        roster_updates: vec![],
        nonce: B32([1; 32]),
        peer_nonce: None,
        keys: vec![],
        policy_ver: None,
        revocation_ver: 0,
        tls_binding: tls,
    });
    assert!(w.hot.on_hello(&hello_p, tls, w.now).is_err());
    let _ = (Bytes::default(), MsgType::Job, ReturnStage::Dkg);
}
