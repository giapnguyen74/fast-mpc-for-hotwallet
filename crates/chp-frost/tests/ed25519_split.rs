//! FROST-Ed25519 δ-split signing: DKG → split → PROD fragment → COLD complete →
//! ed25519-dalek verify_strict; library cross-check; negatives; demonstrations.

use chp_frost::dkg::{ed_group_key, ed_party, ed_verifying_share, run_dkg_2of3, DkgOutput, EdParty};
use chp_frost::ed25519::*;
use chp_frost::Error;
use curve25519_dalek::{EdwardsPoint, Scalar};
use frost_ed25519::{Ed25519Sha512 as E, Identifier};
use rand::RngCore;
use std::collections::BTreeMap;

const KEY_ID: &[u8] = b"sol-hot-1";

struct Fx {
    out: DkgOutput<E>,
    hot_id: Identifier,
    cold_id: Identifier,
    y: EdwardsPoint,
    hot: EdParty,
    cold: EdParty,
    rec: EdParty,
    y_h: EdwardsPoint,
    ids: SignerIds,
}

fn id_sets() -> Vec<[Identifier; 3]> {
    let n = |i: u16| Identifier::try_from(i).unwrap();
    vec![
        [n(1), n(2), n(3)],
        [n(3), n(1), n(2)],
        [
            Identifier::derive(b"HOT").unwrap(),
            Identifier::derive(b"COLD").unwrap(),
            Identifier::derive(b"REC").unwrap(),
        ],
    ]
}

fn fixture(ids3: [Identifier; 3]) -> Fx {
    let out = run_dkg_2of3::<E, _>(ids3, &mut rand::thread_rng()).unwrap();
    let [hot_id, cold_id, rec_id] = ids3;
    let hot = ed_party(&out.key_packages[&hot_id]).unwrap();
    let cold = ed_party(&out.key_packages[&cold_id]).unwrap();
    let rec = ed_party(&out.key_packages[&rec_id]).unwrap();
    let y = ed_group_key(&out.public).unwrap();
    let y_h = ed_verifying_share(&out.public, &hot_id).unwrap();
    assert_eq!(y_h, hot.verifying_share);
    let ids = SignerIds::new(hot.id, cold.id).unwrap();
    // Ed25519 has no post_dkg tweak: Y is the raw Pedersen sum.
    let y_raw = out
        .constant_term_commitments
        .iter()
        .map(|b| decode_point(&b.as_slice().try_into().unwrap()).unwrap())
        .fold(EdwardsPoint::default(), |a, p| a + p);
    assert_eq!(y_raw, y);
    Fx { out, hot_id, cold_id, y, hot, cold, rec, y_h, ids }
}

fn group_secret(f: &Fx) -> Scalar {
    f.ids.lambda_hot() * f.hot.share + f.ids.lambda_cold() * f.cold.share
}

fn rand_msg(len: usize) -> Vec<u8> {
    let mut m = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut m);
    m
}

fn sign_once(f: &Fx, msg: &[u8]) -> Result<(Session, [u8; 64]), Error> {
    let mut rng = rand::thread_rng();
    let key = Ed25519Key::derive(KEY_ID, &f.y, "m")?;
    let (n_h, com_h) = hot_presign_nonces(&mut rng);
    let (n_c, com_c) = presign_nonces(&mut rng);
    let (s_prime_h, delta) = split_share(&f.hot.share, &mut rng);
    let sess_prod = Session::new(&key, f.ids, msg, com_h, com_c)?;
    let z_h = prod_fragment(&sess_prod, n_h, &s_prime_h);
    let sess_cold = Session::new(&key, f.ids, msg, com_h, com_c)?;
    let sig = cold_complete(&sess_cold, &z_h, n_c, &f.cold.share, &delta, &f.y_h)?;
    Ok((sess_cold, sig))
}

#[test]
fn ed25519_end_to_end_verify_strict() {
    for ids in id_sets() {
        let f = fixture(ids);
        assert_eq!(EdwardsPoint::mul_base(&group_secret(&f)), f.y);
        for len in [0, 1, 32, 200] {
            let msg = rand_msg(len);
            let (_, sig) = sign_once(&f, &msg).unwrap();
            verify_strict(&f.y.compress().to_bytes(), &msg, &sig).unwrap();
            // and the frost-ed25519 library verifier agrees
            let vk = frost_ed25519::VerifyingKey::deserialize(&f.y.compress().to_bytes()).unwrap();
            let s = frost_ed25519::Signature::deserialize(&sig).unwrap();
            vk.verify(&msg, &s).unwrap();
        }
        let _ = f.rec;
    }
}

#[test]
fn ed25519_non_root_path_rejected() {
    let f = fixture(id_sets()[0]);
    assert_eq!(Ed25519Key::derive(KEY_ID, &f.y, "m/0"), Err(Error::NonRootEd25519Path));
}

/// Same nonces → our δ-split signature is byte-identical to frost-ed25519's
/// `round2::sign` + `aggregate` (plain FROST with s_h).
#[test]
fn ed25519_matches_frost_ed25519_library() {
    use frost_core::round1::Nonce;
    use frost_ed25519::round1::SigningNonces;
    use frost_ed25519::{aggregate, round2, SigningPackage};
    let mut rng = rand::thread_rng();
    for ids in id_sets() {
        let f = fixture(ids);
        let key = Ed25519Key::derive(KEY_ID, &f.y, "m").unwrap();
        for _ in 0..8 {
            let msg = rand_msg(48);
            let (n_h, com_h) = presign_nonces(&mut rng);
            let (n_c, com_c) = presign_nonces(&mut rng);
            let (dh, eh) = n_h.to_scalars();
            let (dc, ec) = n_c.to_scalars();
            let ln = |d: Scalar, e: Scalar| {
                SigningNonces::from_nonces(
                    Nonce::<E>::deserialize(&d.to_bytes()).unwrap(),
                    Nonce::<E>::deserialize(&e.to_bytes()).unwrap(),
                )
            };
            let (ln_h, ln_c) = (ln(dh, eh), ln(dc, ec));
            let mut cm = BTreeMap::new();
            cm.insert(f.hot_id, *ln_h.commitments());
            cm.insert(f.cold_id, *ln_c.commitments());
            let pkg = SigningPackage::new(cm, &msg);
            let mut shares = BTreeMap::new();
            shares.insert(f.hot_id, round2::sign(&pkg, &ln_h, &f.out.key_packages[&f.hot_id]).unwrap());
            shares.insert(f.cold_id, round2::sign(&pkg, &ln_c, &f.out.key_packages[&f.cold_id]).unwrap());
            let lib_sig: [u8; 64] =
                aggregate(&pkg, &shares, &f.out.public).unwrap().serialize().unwrap().try_into().unwrap();

            let (s_prime_h, delta) = split_share(&f.hot.share, &mut rng);
            let sess = Session::new(&key, f.ids, &msg, com_h, com_c).unwrap();
            let z_h = prod_fragment(&sess, SecretNonces::from_scalars(dh, eh).unwrap(), &s_prime_h);
            let sig = cold_complete(&sess, &z_h, n_c, &f.cold.share, &delta, &f.y_h).unwrap();
            assert_eq!(sig, lib_sig);
            // library share for HOT = our fragment with δ = 0
            let z_h_unmasked = prod_fragment(&sess, SecretNonces::from_scalars(dh, eh).unwrap(), &f.hot.share);
            assert_eq!(shares[&f.hot_id].serialize(), z_h_unmasked.to_bytes().to_vec());
        }
    }
}

#[test]
fn ed25519_zero_sum_and_key_exposure() {
    let mut rng = rand::thread_rng();
    for ids in id_sets() {
        let f = fixture(ids);
        let (s_prime_h, delta) = split_share(&f.hot.share, &mut rng);
        let l = (f.ids.lambda_hot(), f.ids.lambda_cold());
        assert_eq!(l.0 * delta + l.1 * f.ids.mask_ratio() * delta, Scalar::ZERO);
        assert_eq!(l.0 * s_prime_h + l.1 * cold_masked_share(&f.cold.share, &delta, &f.ids), group_secret(&f));
        // key exposure: s′_h − δ = s_h, checkable against public Y_h
        assert_eq!(s_prime_h - delta, f.hot.share);
        assert_eq!(EdwardsPoint::mul_base(&(s_prime_h - delta)), f.y_h);
    }
}

#[test]
fn ed25519_negatives() {
    let mut rng = rand::thread_rng();
    let f = fixture(id_sets()[2]);
    let key = Ed25519Key::derive(KEY_ID, &f.y, "m").unwrap();
    let (m1, m2) = (rand_msg(32), rand_msg(32));
    let (n_h, com_h) = hot_presign_nonces(&mut rng);
    let (n_c, com_c) = presign_nonces(&mut rng);
    let nc = n_c.to_scalars();
    let ncf = || SecretNonces::from_scalars(nc.0, nc.1).unwrap();
    let (s_prime_h, delta) = split_share(&f.hot.share, &mut rng);
    let sess1 = Session::new(&key, f.ids, &m1, com_h, com_c).unwrap();
    let sess2 = Session::new(&key, f.ids, &m2, com_h, com_c).unwrap();
    let z_h = prod_fragment(&sess1, n_h, &s_prime_h);
    let y = f.y.compress().to_bytes();
    let s_c_prime = cold_masked_share(&f.cold.share, &delta, &f.ids);

    // honest
    cold_check_fragment(&sess1, &z_h, &f.y_h, &delta).unwrap();
    // tampered z_h
    let bad = z_h + Scalar::ONE;
    assert_eq!(cold_complete(&sess1, &bad, ncf(), &f.cold.share, &delta, &f.y_h), Err(Error::FaultProdFragment));
    assert_eq!(verify_strict(&y, &m1, &cold_combine(&sess1, &bad, ncf(), &s_c_prime)), Err(Error::FaultFinalVerify));
    // wrong δ
    let wrong = delta + Scalar::ONE;
    assert_eq!(cold_complete(&sess1, &z_h, ncf(), &f.cold.share, &wrong, &f.y_h), Err(Error::FaultProdFragment));
    let s_c_wrong = cold_masked_share(&f.cold.share, &wrong, &f.ids);
    assert_eq!(verify_strict(&y, &m1, &cold_combine(&sess1, &z_h, ncf(), &s_c_wrong)), Err(Error::FaultFinalVerify));
    // fragment for m1 completed by COLD for m2
    assert_eq!(cold_check_fragment(&sess2, &z_h, &f.y_h, &delta), Err(Error::FaultProdFragment));
    let sig = cold_combine(&sess2, &z_h, ncf(), &s_c_prime);
    assert_eq!(verify_strict(&y, &m2, &sig), Err(Error::FaultFinalVerify));
    assert_eq!(verify_strict(&y, &m1, &sig), Err(Error::FaultFinalVerify));
    // wrong verifying share
    assert_eq!(cold_check_fragment(&sess1, &z_h, &f.rec.verifying_share, &delta), Err(Error::FaultProdFragment));
    // honest completion still works
    let sig = cold_complete(&sess1, &z_h, ncf(), &f.cold.share, &delta, &f.y_h).unwrap();
    verify_strict(&y, &m1, &sig).unwrap();
}

/// Three fragments from one reused half → HOT's share (COLD holds δ).
#[test]
fn ed25519_nonce_reuse_leaks_hot_share() {
    let mut rng = rand::thread_rng();
    let f = fixture(id_sets()[0]);
    let key = Ed25519Key::derive(KEY_ID, &f.y, "m").unwrap();
    let (n_h, com_h) = hot_presign_nonces(&mut rng);
    let (dh, eh) = n_h.to_scalars();
    let (s_prime_h, delta) = split_share(&f.hot.share, &mut rng);
    let mut a = [[Scalar::ZERO; 3]; 3];
    let mut z = [Scalar::ZERO; 3];
    for k in 0..3 {
        let (_, com_c) = presign_nonces(&mut rng);
        let sess = Session::new(&key, f.ids, &rand_msg(32), com_h, com_c).unwrap();
        z[k] = prod_fragment(&sess, SecretNonces::from_scalars(dh, eh).unwrap(), &s_prime_h);
        cold_check_fragment(&sess, &z[k], &f.y_h, &delta).unwrap();
        a[k] = [Scalar::ONE, sess.rho_h, sess.lambda_h * sess.c];
    }
    let det = |m: [[Scalar; 3]; 3]| {
        m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1]) - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
            + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0])
    };
    let mut m = a;
    for row in 0..3 {
        m[row][2] = z[row];
    }
    let s_prime = det(m) * det(a).invert();
    assert_eq!(s_prime, s_prime_h);
    assert_eq!(s_prime - delta, f.hot.share);
}
