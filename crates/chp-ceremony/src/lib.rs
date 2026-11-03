//! Offline quorum tooling (DESIGN SP1 §3 enrollment, SP2 DKG, SP3 share export, SP10 book).
//!
//! The ceremony runs on an isolated network. In this prototype the ceremony network is the
//! in-process mesh of `chp_mpc::dkls::local_mesh`; HOT and COLD shares are produced by ceremony
//! instances and delivered to the production enclaves as HPKE share packages (SP3), so the
//! export/import path is exercised. REC's share stays in its (simulated) HSM.

use std::sync::Arc;

use chp_auth::{quorum::Custodians, trust::Pinned};
use chp_core::{address::control_statement, digest::hash_of};
use chp_crypto::{
    derive::{derived_key, t_path},
    ecdsa::{cold_complete, enc_point, prod_fragment},
    seal::seal,
};
use chp_mpc::{
    dkls::{ceremony_instance, local_dkg, local_presign, presign_instance, PARTY_COLD, PARTY_HOT, PARTY_REC},
    half_from_presign, share_to_bytes, Keyshare,
};
use chp_tee::{verify_attestation, Attestation};
use chp_wire::{
    msgs::*,
    Bytes, KeyId, MsgType, Protocol, QuorumRole, Role, B32,
};

#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    #[error("{0}")]
    Failed(String),
}

fn fail<T>(s: impl Into<String>) -> Result<T, CeremonyError> {
    Err(CeremonyError::Failed(s.into()))
}

/// The offline quorums (ceremony + one policy quorum per source).
pub struct Quorum {
    pub ceremony: Custodians,
    pub m: usize,
    pub policy_prod: Custodians,
    pub policy_cold: Custodians,
    pub pm: usize,
    pub releases: Vec<B32>,
}

impl Quorum {
    pub fn new(releases: Vec<B32>) -> Self {
        Quorum { ceremony: Custodians::generate(5), m: 3, policy_prod: Custodians::generate(3), policy_cold: Custodians::generate(3), pm: 2, releases }
    }

    /// Roots compiled into every image.
    pub fn pinned(&self) -> Pinned {
        Pinned {
            rosters: vec![
                Roster { role: QuorumRole::Ceremony, version: 1, members: self.ceremony.members(), threshold: self.m as u8 },
                Roster { role: QuorumRole::PolicyProd, version: 1, members: self.policy_prod.members(), threshold: self.pm as u8 },
                Roster { role: QuorumRole::PolicyCold, version: 1, members: self.policy_cold.members(), threshold: self.pm as u8 },
            ],
            releases: self.releases.clone(),
        }
    }

    /// Ceremony-quorum signature over any public control object.
    pub fn sign<T: serde::Serialize>(&self, t: MsgType, body: &T) -> Vec<u8> {
        self.ceremony.sign(self.m, t, body)
    }

    pub fn sign_policy(&self, b: &PolicyBundle) -> Vec<u8> {
        match b.target {
            Role::Cold => self.policy_cold.sign(self.pm, MsgType::PolicyBundle, b),
            _ => self.policy_prod.sign(self.pm, MsgType::PolicyBundle, b),
        }
    }

    /// Enrollment (DESIGN SP1 §3): verify the vendor chain and that the measurement is on the
    /// signed release list, check `user_data = H(role ‖ replica ‖ id_pk ‖ wrap_pk)`, then sign.
    #[allow(clippy::too_many_arguments)]
    pub fn enroll(&self, att: &Attestation, role: Role, party_index: u8, replica: u8, id_pk: [u8; 32], wrap_pk: [u8; 32], now: u64, ttl: u64) -> Result<Vec<u8>, CeremonyError> {
        if !verify_attestation(att) {
            return fail("attestation does not verify");
        }
        if !self.releases.contains(&att.measurement) {
            return fail("measurement not on the release list");
        }
        if att.user_data != chp_tee::enrollment_user_data(role, replica, &id_pk, &wrap_pk) {
            return fail("attestation does not bind these keys");
        }
        Ok(self.sign(MsgType::PartyCert, &PartyCert {
            role,
            party_index,
            replica,
            id_pk: B32(id_pk),
            wrap_pk: B32(wrap_pk),
            measurement: att.measurement,
            key_ids: vec![],
            not_before: now,
            not_after: now + ttl,
            qr_route: false,
        }))
    }

    /// Enroll a client (UPSTREAM / requester) that runs outside an enclave in the prototype.
    pub fn enroll_client(&self, role: Role, id_pk: [u8; 32], now: u64, ttl: u64) -> Vec<u8> {
        self.sign(MsgType::PartyCert, &PartyCert {
            role,
            party_index: 0,
            replica: 0,
            id_pk: B32(id_pk),
            wrap_pk: B32([0; 32]),
            measurement: B32::default(),
            key_ids: vec![],
            not_before: now,
            not_after: now + ttl,
            qr_route: false,
        })
    }
}

/// REC: offline backup HSM. Holds the third share; ceremonies only; sends nothing at runtime.
pub struct RecHsm {
    share: Arc<Keyshare>,
}

impl RecHsm {
    pub fn share(&self) -> Arc<Keyshare> {
        self.share.clone()
    }
}

/// Everything a DKG ceremony produces (DESIGN SP2 §5).
pub struct DkgOutput {
    pub ceremony_id: B32,
    pub key_id: KeyId,
    pub manifest: Vec<u8>,
    pub book: Vec<u8>,
    pub hot_package: Vec<u8>,
    pub cold_package: Vec<u8>,
    pub rec: RecHsm,
    /// `Y` fingerprints reported by each participant (compared by custodians).
    pub fingerprints: [String; 3],
    pub open: Vec<u8>,
}

/// Inputs naming the production recipients.
pub struct Recipients<'a> {
    pub hot_cert: &'a [u8],
    pub cold_cert: &'a [u8],
    pub hot: &'a PartyCert,
    pub cold: &'a PartyCert,
    pub hot_boot_seq: u64,
    pub cold_boot_seq: u64,
}

async fn two_party_sign(a: &Arc<Keyshare>, b: &Arc<Keyshare>, key_id: &KeyId, path: &str, m: &[u8; 32]) -> Result<[u8; 64], CeremonyError> {
    let (pa, pb) = local_presign(a.clone(), b.clone(), presign_instance(&rand::random(), 0)).await.map_err(|e| CeremonyError::Failed(e.to_string()))?;
    let y = a.public_key();
    let t = t_path(&key_id.0, &y, path);
    let f = prod_fragment(half_from_presign(&pa), m, &t).map_err(|e| CeremonyError::Failed(e.to_string()))?;
    let s = cold_complete(half_from_presign(&pb), &f, m, &t, &derived_key(&key_id.0, &y, path)).map_err(|e| CeremonyError::Failed(e.to_string()))?;
    Ok(s.sig)
}

/// HPKE `info` of a share package (DESIGN SP3 §4 step 1).
pub fn share_info(key_id: &KeyId, version: u32, party_index: u8, ceremony_id: &B32) -> Vec<u8> {
    let mut v = b"chp-share-v1".to_vec();
    v.extend_from_slice(&key_id.0);
    v.extend_from_slice(&version.to_be_bytes());
    v.push(party_index);
    v.extend_from_slice(&ceremony_id.0);
    v
}

/// Run a DKG ceremony (DESIGN SP2 §3) for an EVM chain and the given address paths.
pub async fn run_dkg(q: &Quorum, chain: &str, paths: &[&str], r: Recipients<'_>, now: u64) -> Result<DkgOutput, CeremonyError> {
    let ceremony_id = B32(rand::random());
    let key_id = B32(rand::random());
    let open = q.sign(MsgType::CeremonyOpen, &CeremonyOpen {
        ceremony_id,
        kind: CeremonyKind::Dkg,
        key_id,
        key_version: 1,
        participants: vec![Role::Hot, Role::Cold, Role::Rec],
        not_after: now + 3600,
        boot_seq: vec![(Role::Hot, r.hot_boot_seq), (Role::Cold, r.cold_boot_seq), (Role::Rec, 1)],
    });
    // DKG rounds among the three participants.
    let shares: Vec<Arc<Keyshare>> = local_dkg(ceremony_instance(&ceremony_id.0, "dkg"))
        .await
        .map_err(|e| CeremonyError::Failed(e.to_string()))?
        .into_iter()
        .map(Arc::new)
        .collect();
    let (h, c, rec) = (&shares[PARTY_HOT as usize], &shares[PARTY_COLD as usize], &shares[PARTY_REC as usize]);
    // Agreement: every party outputs the same Y and public-share list; custodians compare.
    let fps: Vec<String> = shares.iter().map(|s| hex::encode(&enc_point(&s.public_key())[..9])).collect();
    if fps[0] != fps[1] || fps[1] != fps[2] {
        return fail("Y fingerprints differ: ceremony aborted");
    }
    for i in 0..3u8 {
        if shares.iter().any(|s| s.big_s(i) != shares[0].big_s(i)) {
            return fail("public share lists differ");
        }
    }
    let y = h.public_key();
    // Test signature with each pair {H,C} {H,R} {C,R}, verified against Y.
    for (a, b) in [(h, c), (h, rec), (c, rec)] {
        two_party_sign(a, b, &key_id, "m", &rand::random()).await?;
    }
    let manifest = q.sign(MsgType::KeyManifest, &KeyManifest {
        key_id,
        key_version: 1,
        protocol: Protocol::Dkls23Secp256k1,
        chain: chain.into(),
        group_key: Bytes(enc_point(&y).to_vec()),
        parties: vec![
            ManifestParty { role: Role::Hot, party_index: PARTY_HOT, public_share: Bytes(enc_point(&y_i(h, PARTY_HOT)).to_vec()), cert_hash: hash_of(r.hot_cert) },
            ManifestParty { role: Role::Cold, party_index: PARTY_COLD, public_share: Bytes(enc_point(&y_i(h, PARTY_COLD)).to_vec()), cert_hash: hash_of(r.cold_cert) },
            ManifestParty { role: Role::Rec, party_index: PARTY_REC, public_share: Bytes(enc_point(&y_i(h, PARTY_REC)).to_vec()), cert_hash: B32::default() },
        ],
        ceremony_id,
    });
    let manifest_hash = hash_of(&manifest);
    // Address book: per path, derive the address and have the key sign the control statement.
    let mut entries = Vec::new();
    for p in paths {
        let addr = chp_chain::evm::address_of_point(&derived_key(&key_id.0, &y, p));
        let st = control_statement(chain, &key_id, p, &addr);
        let sig = two_party_sign(h, c, &key_id, p, &st).await?;
        entries.push(AddressEntry { chain: chain.into(), path: p.to_string(), encoding: "evm-keccak".into(), address: addr, status: AddressStatus::Active, valid_from: now, control_sig: Bytes(sig.to_vec()) });
    }
    let book = q.sign(MsgType::AddressBook, &AddressBook { key_id, key_version: 1, manifest_hash, book_version: 1, entries });
    // SP3 export: HPKE-seal each live share to its recipient's attested wrap_pk.
    let mut rng = rand::thread_rng();
    let mut package = |share: &Keyshare, idx: u8, wrap: &B32| -> Result<Vec<u8>, CeremonyError> {
        let s = seal(&wrap.0, &share_info(&key_id, 1, idx, &ceremony_id), &[], &share_to_bytes(share), &mut rng).map_err(|e| CeremonyError::Failed(e.to_string()))?;
        Ok(q.sign(MsgType::SharePackage, &SharePackage { key_id, key_version: 1, party_index: idx, ceremony_id, manifest_hash, sealed: Sealed { enc: Bytes(s.enc), ct: Bytes(s.ct) } }))
    };
    let hot_package = package(h, PARTY_HOT, &r.hot.wrap_pk)?;
    let cold_package = package(c, PARTY_COLD, &r.cold.wrap_pk)?;
    Ok(DkgOutput {
        ceremony_id,
        key_id,
        manifest,
        book,
        hot_package,
        cold_package,
        rec: RecHsm { share: rec.clone() },
        fingerprints: [fps[0].clone(), fps[1].clone(), fps[2].clone()],
        open,
    })
}

fn y_i(s: &Keyshare, party: u8) -> k256::ProjectivePoint {
    s.big_s(party)
}

/// Verify a `ShareReceipt` against the manifest before signing `Activate` (DESIGN SP3 §4 step 5).
pub fn check_receipt(receipt: &[u8], cert: &PartyCert, manifest_hash: &B32) -> Result<ShareReceipt, CeremonyError> {
    let (_, body) = chp_auth::link::check_standalone(cert, Role::Rec, receipt, MsgType::ShareReceipt).map_err(|e| CeremonyError::Failed(e.to_string()))?;
    let r: ShareReceipt = chp_wire::decode_canonical(&body).map_err(|e| CeremonyError::Failed(e.to_string()))?;
    if r.manifest_hash != *manifest_hash || r.measurement != cert.measurement {
        return fail("receipt does not match the manifest or the enrolled measurement");
    }
    Ok(r)
}
