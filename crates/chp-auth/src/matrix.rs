//! Authorization matrix (DESIGN SP1 §6). Anything not listed is refused, even with a valid
//! signature. Quorum-signed objects never travel as `SignedMsg`; they have no sender role here
//! and are checked by [`crate::trust::Trust::verify_quorum`].

use chp_wire::{MsgType, Role};

/// May `from` send a `SignedMsg` of type `t` to `to`?
pub fn may_send(t: MsgType, from: Role, to: Role) -> bool {
    use MsgType as T;
    use Role::*;
    match t {
        // Links exist only COLD→HOT and COLD→PROD; HOT and PROD refuse each other's hellos.
        T::LinkHello => matches!((from, to), (Cold, Hot) | (Cold, Prod) | (Hot, Cold) | (Prod, Cold)),
        T::WakeOpen => (from, to) == (Cold, Hot),
        T::WakeAccept => (from, to) == (Hot, Cold),
        T::WakeClose => matches!((from, to), (Cold, Hot) | (Hot, Cold)),
        T::QuorumFile => (from, to) == (Cold, Hot),
        T::PresignOpen => (from, to) == (Cold, Hot),
        T::PresignAccept | T::PresignRefuse | T::PresignStored | T::ShareMasks => (from, to) == (Hot, Cold),
        T::PresignMsg | T::FrostCommitments => matches!((from, to), (Cold, Hot) | (Hot, Cold)),
        // HOT → PROD only via media (signed transfer inside an unsigned MediaBundle).
        T::PresigTransfer => (from, to) == (Hot, Prod),
        T::TransferAck | T::PoolStatus | T::Job => (from, to) == (Prod, Cold),
        T::PresignActivate | T::Status | T::OrphanDelete => (from, to) == (Cold, Prod),
        T::PresignAbort => matches!((from, to), (Cold, Prod) | (Prod, Cold)),
        T::FreezeNotice => matches!((from, to), (Cold, Prod) | (Prod, Cold) | (Cold, Hot) | (Hot, Cold)),
        // Receipts go to the quorum (modelled as receiver role `Rec`-less: any).
        T::ShareReceipt => matches!(from, Hot | Cold | Rec),
        T::WithdrawalEnvelope => (from, to) == (Upstream, Prod) || (from, to) == (Upstream, Cold),
        T::AddressQuery => matches!(from, Upstream | Requester) && to == Prod,
        T::AddressProof | T::NotFound => from == Prod && matches!(to, Upstream | Requester),
        T::CeremonyRound => matches!(from, Hot | Cold | Rec) && matches!(to, Hot | Cold | Rec) && from != to,
        // Quorum-only or unsigned types.
        T::PartyCert | T::RosterUpdate | T::RevocationList | T::CeremonyOpen | T::KeyManifest
        | T::SharePackage | T::Activate | T::Retire | T::Unfreeze | T::PolicyBundle
        | T::QrPairing | T::AddressBook | T::MediaBundle => false,
    }
}

/// Types allowed on the QR channel (DESIGN SP9 §4).
pub fn qr_allowed(t: MsgType, from: Role) -> bool {
    use MsgType as T;
    match from {
        Role::Prod => matches!(t, T::Job | T::TransferAck | T::PoolStatus | T::PresignAbort | T::FreezeNotice),
        Role::Cold => matches!(t, T::Status | T::PresignActivate | T::PresignAbort | T::OrphanDelete | T::FreezeNotice),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Role::*;

    #[test]
    fn rec_sends_nothing_at_runtime() {
        for t in MsgType::ALL {
            if *t == MsgType::ShareReceipt || *t == MsgType::CeremonyRound {
                continue; // ceremony network only
            }
            for to in Role::ALL {
                assert!(!may_send(*t, Rec, to), "{t:?}");
            }
        }
    }

    #[test]
    fn prod_cannot_presign_or_touch_keys() {
        for t in [
            MsgType::PresignOpen, MsgType::PresignMsg, MsgType::FrostCommitments, MsgType::PresignAccept,
            MsgType::SharePackage, MsgType::CeremonyRound, MsgType::WakeOpen, MsgType::QuorumFile,
            MsgType::Status, MsgType::PresignActivate,
        ] {
            for to in Role::ALL {
                assert!(!may_send(t, Prod, to), "{t:?} → {to:?}");
            }
        }
    }

    #[test]
    fn hot_cannot_send_jobs_or_talk_to_prod_over_a_link() {
        for to in Role::ALL {
            assert!(!may_send(MsgType::Job, Hot, to));
            assert!(!may_send(MsgType::TransferAck, Hot, to));
        }
        assert!(!may_send(MsgType::LinkHello, Hot, Prod));
        assert!(!may_send(MsgType::LinkHello, Prod, Hot));
    }

    #[test]
    fn quorum_objects_never_travel_as_signed_msgs() {
        for t in [
            MsgType::PartyCert, MsgType::KeyManifest, MsgType::Activate, MsgType::Unfreeze,
            MsgType::RevocationList, MsgType::Retire, MsgType::SharePackage, MsgType::AddressBook,
            MsgType::PolicyBundle, MsgType::CeremonyOpen, MsgType::QrPairing, MsgType::RosterUpdate,
        ] {
            for from in Role::ALL {
                for to in Role::ALL {
                    assert!(!may_send(t, from, to));
                }
            }
        }
    }
}
