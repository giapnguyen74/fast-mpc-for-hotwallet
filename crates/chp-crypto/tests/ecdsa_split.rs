//! Phase 0.1–0.3 validation: DKLs23 presign halves + CHP's online step (DESIGN SP6 §4.1).

use std::sync::Arc;

use chp_crypto::{
    derive::{derived_key, t_path, ROOT_PATH},
    dkls::{local_dkg, local_mesh, local_presign, presign_instance, refresh},
    ecdsa::{cold_complete, key_from_both_halves, prod_fragment, r_scalar, EcdsaHalf},
    verify::{ecdsa_recover, ecdsa_verify},
    CryptoError,
};
use k256::{
    ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey},
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    ProjectivePoint, Scalar,
};
use sl_dkls23::keygen::Keyshare;

const KEY_ID: &[u8] = b"test-key";

async fn dkg() -> Vec<Arc<Keyshare>> {
    local_dkg(rand::random()).await.unwrap().into_iter().map(Arc::new).collect()
}

async fn halves(a: &Arc<Keyshare>, b: &Arc<Keyshare>) -> (EcdsaHalf, EcdsaHalf) {
    let (pa, pb) = local_presign(a.clone(), b.clone(), presign_instance(&rand::random(), 1)).await.unwrap();
    (EcdsaHalf::from_presign(&pa), EcdsaHalf::from_presign(&pb))
}

fn sign(h: EcdsaHalf, c: EcdsaHalf, m: &[u8; 32], path: &str, y: &ProjectivePoint) -> Result<[u8; 64], CryptoError> {
    let t = t_path(KEY_ID, y, path);
    let yp = derived_key(KEY_ID, y, path);
    let frag = prod_fragment(h, m, &t)?;
    cold_complete(c, &frag, m, &t, &yp).map(|s| s.sig)
}

#[tokio::test(flavor = "multi_thread")]
async fn dkg_agrees_on_group_key() {
    let s = dkg().await;
    assert_eq!(s.len(), 3);
    assert_eq!(s[0].public_key(), s[1].public_key());
    assert_eq!(s[1].public_key(), s[2].public_key());
    // public shares: each party's s_i·G is consistent across parties' views
    for i in 0..3u8 {
        assert_eq!(s[0].big_s(i), s[1].big_s(i));
        assert_eq!(s[0].big_s(i), s[2].big_s(i));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn split_signing_root_path_verifies_independently() {
    let s = dkg().await;
    let y = s[0].public_key();
    let (h, c) = halves(&s[0], &s[1]).await;
    assert_eq!(h.sid, c.sid);
    assert_eq!(h.big_r, c.big_r);
    let m: [u8; 32] = rand::random();
    let t = t_path(KEY_ID, &y, ROOT_PATH);
    assert_eq!(t, Scalar::ZERO);
    let frag = prod_fragment(h, &m, &t).unwrap();
    let sig = cold_complete(c, &frag, &m, &t, &y).unwrap();
    // libsecp256k1 (inside cold_complete) and k256 both accept.
    let vk = VerifyingKey::from_affine(y.to_affine()).unwrap();
    vk.verify_prehash(&m, &Signature::from_slice(&sig.sig).unwrap()).unwrap();
    // recovery id is correct
    let rec = ecdsa_recover(&m, &sig.sig, sig.recid).unwrap();
    assert_eq!(&rec[..], y.to_affine().to_encoded_point(false).as_bytes());
    // low-s
    let s_scalar = Scalar::from_repr(<[u8; 32]>::try_from(&sig.sig[32..]).unwrap().into()).unwrap();
    assert!(!bool::from(k256::elliptic_curve::scalar::IsHigh::is_high(&s_scalar)));
}

#[tokio::test(flavor = "multi_thread")]
async fn split_signing_with_path_tweak_m_plus_r_t() {
    let s = dkg().await;
    let y = s[0].public_key();
    for i in 0..8 {
        let path = format!("m/withdraw/{i}");
        let (h, c) = halves(&s[0], &s[1]).await;
        let m: [u8; 32] = rand::random();
        let sig = sign(h, c, &m, &path, &y).unwrap();
        let yp = derived_key(KEY_ID, &y, &path);
        ecdsa_verify(&yp, &m, &sig).unwrap();
        // the signature is for the derived key, not for Y
        assert!(ecdsa_verify(&y, &m, &sig).is_err());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn every_pair_of_share_holders_can_sign() {
    // DESIGN SP2 §3: test signature with each pair {H,C} {H,R} {C,R}.
    let s = dkg().await;
    let y = s[0].public_key();
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        let (h, c) = halves(&s[a], &s[b]).await;
        let m: [u8; 32] = rand::random();
        sign(h, c, &m, "m/0", &y).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn both_halves_are_key_equivalent() {
    // DESIGN §6: x = Σs₀′ / (r·Σφ). This documents the risk; it must keep holding.
    let s = dkg().await;
    let y = s[0].public_key();
    let (h, c) = halves(&s[0], &s[1]).await;
    let x = key_from_both_halves(&h, &c).unwrap();
    assert_eq!(ProjectivePoint::GENERATOR * x, y);
}

#[tokio::test(flavor = "multi_thread")]
async fn reusing_a_presignature_leaks_the_key() {
    // Documents why take = delete (rule 3) and the hardware counter (§6.1) are mandatory.
    let s = dkg().await;
    let y = s[0].public_key();
    let (h, c) = halves(&s[0], &s[1]).await;
    let (m1, m2): ([u8; 32], [u8; 32]) = (rand::random(), rand::random());
    let sig1 = sign(h.duplicate_for_test(), c.duplicate_for_test(), &m1, ROOT_PATH, &y).unwrap();
    let sig2 = sign(h, c, &m2, ROOT_PATH, &y).unwrap();
    let sc = |b: &[u8]| Scalar::from_repr(<[u8; 32]>::try_from(b).unwrap().into()).unwrap();
    let r = sc(&sig1[..32]);
    assert_eq!(r, sc(&sig2[..32]), "same nonce");
    let (s1, s2) = (sc(&sig1[32..]), sc(&sig2[32..]));
    let (z1, z2) = (chp_crypto::ecdsa::msg_scalar(&m1), chp_crypto::ecdsa::msg_scalar(&m2));
    // low-s normalisation hides the sign of s: try both.
    let mut found = false;
    for sign2 in [s2, -s2] {
        let k = (z1 - z2) * (s1 - sign2).invert().unwrap();
        for kk in [k, -k] {
            let x = (s1 * kk - z1) * r.invert().unwrap();
            if ProjectivePoint::GENERATOR * x == y {
                found = true;
            }
        }
    }
    assert!(found, "nonce reuse must reveal x");
}

#[tokio::test(flavor = "multi_thread")]
async fn tampered_or_mismatched_fragments_fail_final_verify() {
    let s = dkg().await;
    let y = s[0].public_key();
    let m: [u8; 32] = rand::random();
    let t = Scalar::ZERO;

    // 1. tampered s0
    let (h, c) = halves(&s[0], &s[1]).await;
    let mut f = prod_fragment(h, &m, &t).unwrap();
    f.s0[31] ^= 1;
    assert_eq!(cold_complete(c, &f, &m, &t, &y).unwrap_err(), CryptoError::FinalVerify);

    // 2. fragment computed for another message (PROD swapped the request)
    let (h, c) = halves(&s[0], &s[1]).await;
    let other: [u8; 32] = rand::random();
    let f = prod_fragment(h, &other, &t).unwrap();
    assert_eq!(cold_complete(c, &f, &m, &t, &y).unwrap_err(), CryptoError::FinalVerify);

    // 3. fragment computed for another path
    let (h, c) = halves(&s[0], &s[1]).await;
    let f = prod_fragment(h, &m, &t_path(KEY_ID, &y, "m/evil")).unwrap();
    assert_eq!(cold_complete(c, &f, &m, &t, &y).unwrap_err(), CryptoError::FinalVerify);

    // 4. fragment from another presignature (sid mismatch)
    let (h1, _c1) = halves(&s[0], &s[1]).await;
    let (_h2, c2) = halves(&s[0], &s[1]).await;
    let f = prod_fragment(h1, &m, &t).unwrap();
    assert_eq!(cold_complete(c2, &f, &m, &t, &y).unwrap_err(), CryptoError::InvalidPresign);

    // 5. sid relabelled to match, but values from another presignature
    let (h1, _c1) = halves(&s[0], &s[1]).await;
    let (_h2, c2) = halves(&s[0], &s[1]).await;
    let mut f = prod_fragment(h1, &m, &t).unwrap();
    f.sid = c2.sid;
    assert_eq!(cold_complete(c2, &f, &m, &t, &y).unwrap_err(), CryptoError::FinalVerify);
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_keeps_group_key_and_old_new_mix_fails() {
    // DESIGN SP8 §2: new shares, same Y; every pair of NEW shares signs; old + new must FAIL.
    let old = dkg().await;
    let y = old[0].public_key();
    let (relays, pump) = local_mesh(3);
    let inst: [u8; 32] = rand::random();
    let mut set = tokio::task::JoinSet::new();
    for (sh, r) in old.iter().cloned().zip(relays) {
        set.spawn(async move { refresh(&sh, inst, rand::random(), r).await });
    }
    let mut new = Vec::new();
    while let Some(r) = set.join_next().await {
        new.push(Arc::new(r.unwrap().unwrap()));
    }
    pump.abort();
    new.sort_by_key(|s| s.party_id);
    for n in &new {
        assert_eq!(n.public_key(), y);
    }
    for i in 0..3 {
        assert_ne!(new[i].s_i(), old[i].s_i(), "share {i} must change");
    }
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        let (h, c) = halves(&new[a], &new[b]).await;
        sign(h, c, &rand::random(), "m/0", &y).unwrap();
    }
    // old HOT + new COLD: presign must refuse (library consistency check), or signing must fail.
    let res = local_presign(old[0].clone(), new[1].clone(), presign_instance(&rand::random(), 1)).await;
    match res {
        Err(_) => {}
        Ok((pa, pb)) => {
            let r = sign(EcdsaHalf::from_presign(&pa), EcdsaHalf::from_presign(&pb), &rand::random(), ROOT_PATH, &y);
            assert!(r.is_err(), "old+new shares must not produce a valid signature");
        }
    }
}

#[test]
fn r_scalar_matches_signature_r() {
    // sanity: r = R.x mod q for a known point (G).
    let r = r_scalar(&ProjectivePoint::GENERATOR);
    assert_eq!(
        hex::encode(r.to_bytes()),
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );
}
