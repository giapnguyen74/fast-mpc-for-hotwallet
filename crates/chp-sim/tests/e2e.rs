//! End-to-end: SP1 → SP2 → SP3 → SP4 → SP5 → SP6.

use chp_sim::*;
use chp_wire::msgs::{AddressBook, Outcome};
use chp_wire::MsgType;

#[tokio::test(flavor = "multi_thread")]
async fn full_lifecycle_signs_a_withdrawal() {
    let mut w = World::setup(Options::default()).await;
    let batches = w.refill(PATH, 2).await;
    assert_eq!(batches.len(), 2);
    assert_eq!(w.prod.available(&w.pool(PATH)), 8, "two active batches of 4 at PROD");

    let job = w.withdraw(DEST, 1_000_000_000_000_000_000, PATH).await.expect("admitted");
    let st = w.status_of(job).expect("COLD answered");
    assert_eq!(st.outcome, Outcome::Signed, "{}", st.reason);
    assert_eq!(w.broadcasts.len(), 1, "PROD broadcast the signed tx");

    // The signature recovers to the address the ceremony put in the quorum-signed book.
    let book: AddressBook = w.prod.trust.verify_quorum(&w.book, MsgType::AddressBook).unwrap();
    let addr = &book.entries.iter().find(|e| e.path == PATH).unwrap().address;
    assert_eq!(&recover_sender(&w.broadcasts[0].1), addr);

    // Each side burned exactly one presignature.
    assert_eq!(w.prod.available(&w.pool(PATH)), 7);
    assert_eq!(w.cold.pool(&w.pool(PATH)).unwrap().active_ids().len(), 7);

    // A second withdrawal uses the next id.
    let j2 = w.withdraw(DEST, 5, PATH).await.unwrap();
    assert_eq!(w.status_of(j2).unwrap().outcome, Outcome::Signed);
    assert_eq!(w.broadcasts.len(), 2);
    assert_ne!(w.broadcasts[0].2, w.broadcasts[1].2);
}
