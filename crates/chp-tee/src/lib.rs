//! Simulated TEE / HSM (PLAN §0: simulator only).
//!
//! What is simulated, and what a real backend would provide instead:
//!
//! | Simulated here | Real backend |
//! |---|---|
//! | [`Enclave::id`] Ed25519 identity key, [`Enclave::wrap`] X25519 wrap key | keys generated and kept inside the TEE/HSM |
//! | [`attest`] signed by a fixed "vendor" key | vendor attestation chain (SEV-SNP, TDX, Nitro, HSM) |
//! | [`HwCounters`] monotonic counters that survive a storage restore | TPM 2.0 NV counter, HSM counter object, RPMB (DESIGN §6.1) |
//!
//! Persistent state of an engine is a serialisable blob ("sealed storage"). Tests model a
//! storage restore by putting an old blob back while the [`HwCounters`] keep their values.

use std::collections::BTreeMap;

use chp_crypto::{ident::IdKey, seal::WrapKey};
use chp_wire::B32;
use serde::{Deserialize, Serialize};

/// Fixed seed of the simulated attestation vendor.
const VENDOR_SEED: [u8; 32] = *b"chp-sim-attestation-vendor-key!!";

/// Public key of the simulated attestation vendor (pinned in every image).
pub fn vendor_pk() -> [u8; 32] {
    IdKey::from_seed(VENDOR_SEED).public()
}

/// A simulated attestation report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub measurement: B32,
    pub user_data: B32,
    pub vendor_sig: chp_wire::B64,
}

fn att_msg(measurement: &B32, user_data: &B32) -> Vec<u8> {
    let mut m = b"chp-sim-attest-v1".to_vec();
    m.extend_from_slice(&measurement.0);
    m.extend_from_slice(&user_data.0);
    m
}

/// Produce an attestation over `user_data` for an enclave with `measurement`.
pub fn attest(measurement: B32, user_data: B32) -> Attestation {
    let sig = IdKey::from_seed(VENDOR_SEED).sign(&att_msg(&measurement, &user_data));
    Attestation { measurement, user_data, vendor_sig: chp_wire::B64(sig) }
}

/// Verify an attestation against the vendor root.
pub fn verify_attestation(a: &Attestation) -> bool {
    chp_crypto::ident::verify(&vendor_pk(), &att_msg(&a.measurement, &a.user_data), &a.vendor_sig.0).is_ok()
}

/// Hardware monotonic counters (DESIGN §6.1). They live outside restorable storage.
/// A counter can only go up by one per increment and keeps its value across restarts.
#[derive(Default, Debug)]
pub struct HwCounters {
    c: BTreeMap<String, u64>,
}

impl HwCounters {
    pub fn read(&self, name: &str) -> u64 {
        *self.c.get(name).unwrap_or(&0)
    }
    /// Increment by exactly one and return the new value.
    pub fn increment(&mut self, name: &str) -> u64 {
        let v = self.c.entry(name.to_string()).or_insert(0);
        *v += 1;
        *v
    }
    pub fn names(&self) -> Vec<String> {
        self.c.keys().cloned().collect()
    }
}

/// A simulated enclave: keys, measurement and hardware counters.
pub struct Enclave {
    pub id: IdKey,
    pub wrap: WrapKey,
    pub measurement: B32,
    pub counters: HwCounters,
}

impl Enclave {
    pub fn new(measurement: B32) -> Self {
        let mut rng = rand::thread_rng();
        Enclave { id: IdKey::generate(&mut rng), wrap: WrapKey::generate(&mut rng), measurement, counters: HwCounters::default() }
    }

    /// Attestation binding this enclave's keys: `user_data = H(role ‖ replica ‖ id_pk ‖ wrap_pk)`
    /// (DESIGN SP1 §3).
    pub fn attest_keys(&self, role: chp_wire::Role, replica: u8) -> Attestation {
        attest(self.measurement, enrollment_user_data(role, replica, &self.id.public(), &self.wrap.public()))
    }
}

/// `H(role ‖ replica ‖ id_pk ‖ wrap_pk)`.
pub fn enrollment_user_data(role: chp_wire::Role, replica: u8, id_pk: &[u8; 32], wrap_pk: &[u8; 32]) -> B32 {
    let role_b = chp_wire::encode(&role);
    B32(chp_crypto::hash::tagged_hash(b"chp-enroll-v1", &[&role_b, &[replica], id_pk, wrap_pk]))
}

/// Measurement of a simulated image (stands in for the enclave measurement of a release).
pub fn measurement_of(image: &str) -> B32 {
    B32(chp_crypto::hash::tagged_hash(b"chp-sim-measurement", &[image.as_bytes()]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_monotonic() {
        let mut c = HwCounters::default();
        assert_eq!(c.read("x"), 0);
        assert_eq!(c.increment("x"), 1);
        assert_eq!(c.increment("x"), 2);
        assert_eq!(c.read("x"), 2);
    }

    #[test]
    fn attestation_verifies_and_binds() {
        let e = Enclave::new(measurement_of("cold-1.0"));
        let a = e.attest_keys(chp_wire::Role::Cold, 0);
        assert!(verify_attestation(&a));
        let mut b = a.clone();
        b.measurement = measurement_of("evil");
        assert!(!verify_attestation(&b));
    }
}
