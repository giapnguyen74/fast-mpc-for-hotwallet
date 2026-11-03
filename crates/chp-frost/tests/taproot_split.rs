//! FROST-Taproot δ-split signing: DKG → HOT presign/split → PROD fragment →
//! COLD check/complete → independent BIP340 verification; negatives; demonstrations.

use chp_frost::dkg::{run_dkg_2of3, secp_group_key, secp_party, secp_verifying_share, DkgOutput, SecpParty};
use chp_frost::secp::*;
use chp_frost::taproot::{has_odd_y, TaprootKey};
use chp_frost::Error;
use frost_secp256k1_tr::{Identifier, Secp256K1Sha256TR as S};
use k256::elliptic_curve::{Field, PrimeField};
use k256::{ProjectivePoint, Scalar};
use rand::{Rng, RngCore};
use std::collections::BTreeMap;

const KEY_ID: &[u8] = b"btc-hot-1";

struct Fx {
    out: DkgOutput<S>,
    hot_id: Identifier,
    cold_id: Identifier,
    rec_id: Identifier,
    y: ProjectivePoint,
    hot: SecpParty,
    cold: SecpParty,
    rec: SecpParty,
    /// Y_h as COLD reads it from the public key package / manifest.
    y_h: ProjectivePoint,
    ids: SignerIds,
}

/// HOT, COLD, REC identifiers: numeric (1,2,3), numeric with i_h > i_c, or derived from names.
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
    let mut rng = rand::thread_rng();
    let out = run_dkg_2of3::<S, _>(ids3, &mut rng).unwrap();
    let [hot_id, cold_id, rec_id] = ids3;
    let hot = secp_party(&out.key_packages[&hot_id]).unwrap();
    let cold = secp_party(&out.key_packages[&cold_id]).unwrap();
    let rec = secp_party(&out.key_packages[&rec_id]).unwrap();
    let y = secp_group_key(&out.public).unwrap();
    let y_h = secp_verifying_share(&out.public, &hot_id).unwrap();
    assert_eq!(y_h, hot.verifying_share);
    for p in [&hot, &cold, &rec] {
        assert_eq!(ProjectivePoint::GENERATOR * p.share, p.verifying_share);
    }
    let ids = SignerIds::new(hot.id, cold.id).unwrap();
    Fx { out, hot_id, cold_id, rec_id, y, hot, cold, rec, y_h, ids }
}

/// Reconstruct x = λ_h·s_h + λ_c·s_c (tests only — never done in CHP).
fn group_secret(f: &Fx) -> Scalar {
    f.ids.lambda_hot() * f.hot.share + f.ids.lambda_cold() * f.cold.share
}

struct Run {
    session: Session,
    sig: [u8; 64],
}

/// One full signature through the CHP roles.
fn sign_once(f: &Fx, key: &TaprootKey, msg: &[u8]) -> Result<Run, Error> {
    let mut rng = rand::thread_rng();
    // SP4 presign (HOT ⇄ COLD): nonce pairs, commitments exchanged.
    let (n_h, com_h) = hot_presign_nonces(&mut rng);
    let (n_c, com_c) = presign_nonces(&mut rng);
    // SP5 step 1 (HOT): split. s′_h → PROD, δ → COLD. HOT erases.
    let (s_prime_h, delta) = split_share(&f.hot.share, &mut rng);
    // SP6 step 3 (PROD): public session + fragment.
    let sess_prod = Session::new(key, f.ids, msg, com_h, com_c)?;
    let z_h = prod_fragment(&sess_prod, n_h, &s_prime_h);
    // SP6 step 5 (COLD): own session, check, complete, verify.
    let sess_cold = Session::new(key, f.ids, msg, com_h, com_c)?;
    assert_eq!((sess_prod.r, sess_prod.c, sess_prod.rho_h, sess_prod.rho_c),
               (sess_cold.r, sess_cold.c, sess_cold.rho_h, sess_cold.rho_c));
    let sig = cold_complete(&sess_cold, &z_h, n_c, &f.cold.share, &delta, &f.y_h)?;
    Ok(Run { session: sess_cold, sig })
}

/// Second independent verifier (k256's BIP340 implementation), besides libsecp256k1.
fn k256_verify(q_x: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let vk = k256::schnorr::VerifyingKey::from_bytes(q_x).unwrap();
    let sig = k256::schnorr::Signature::try_from(&sig[..]).unwrap();
    vk.verify_raw(msg, &sig).is_ok()
}

fn assert_valid(key: &TaprootKey, msg: &[u8], sig: &[u8; 64]) {
    verify_bip340(&key.q_xonly(), msg, sig).expect("libsecp256k1 verify");
    assert!(k256_verify(&key.q_xonly(), msg, sig), "k256 verify");
}

fn rand_msg() -> [u8; 32] {
    let mut m = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut m);
    m
}

// ---------------------------------------------------------------------------
// Positive
// ---------------------------------------------------------------------------

#[test]
fn dkg_all_parties_agree_and_shares_interpolate() {
    for ids in id_sets() {
        let f = fixture(ids);
        let x = group_secret(&f);
        assert_eq!(ProjectivePoint::GENERATOR * x, f.y);
        // any other pair interpolates to the same x
        let hr = SignerIds::new(f.hot.id, f.rec.id).unwrap();
        assert_eq!(hr.lambda_hot() * f.hot.share + hr.lambda_cold() * f.rec.share, x);
        assert_eq!(f.out.key_packages.len(), 3);
        let _ = (f.cold_id, f.rec_id);
    }
}

#[test]
fn taproot_root_path_end_to_end() {
    for ids in id_sets() {
        let f = fixture(ids);
        let key = TaprootKey::derive(KEY_ID, &f.y, "m").unwrap();
        assert_eq!(key.t_path, Scalar::ZERO);
        assert_eq!(key.p, f.y);
        for _ in 0..8 {
            let msg = rand_msg();
            let run = sign_once(&f, &key, &msg).unwrap();
            assert_valid(&key, &msg, &run.sig);
        }
    }
}

/// Signing-key invariant of SP6 §4.2: (g·x + t_eff)·G = g_Q·Q, on many paths.
#[test]
fn taproot_signing_key_invariant() {
    let f = fixture(id_sets()[0]);
    let x = group_secret(&f);
    for i in 0..64 {
        let key = TaprootKey::derive(KEY_ID, &f.y, &format!("m/{i}")).unwrap();
        assert_eq!(key.p, f.y + ProjectivePoint::GENERATOR * key.t_path);
        assert_eq!(ProjectivePoint::GENERATOR * (key.g * x + key.t_eff), key.q_even());
        assert!(!has_odd_y(&key.q_even()));
    }
}

/// Many random paths; loop until odd-y P, odd-y Q and odd-y R (and their even
/// counterparts) have each occurred, then assert the counts.
#[test]
fn taproot_many_paths_all_parity_cases() {
    let mut rng = rand::thread_rng();
    for ids in id_sets() {
        let f = fixture(ids);
        // [P, Q, R] × [even, odd]
        let mut cnt = [[0u32; 2]; 3];
        // all 8 (P,Q,R) parity combinations
        let mut combos = [0u32; 8];
        let mut n = 0;
        while n < 400 {
            let path = format!("m/{}/{}", rng.gen::<u16>(), rng.gen::<u32>());
            let key = TaprootKey::derive(KEY_ID, &f.y, &path).unwrap();
            let msg = rand_msg();
            let run = sign_once(&f, &key, &msg).unwrap();
            assert_valid(&key, &msg, &run.sig);
            let (p, q, r) = (key.p_odd as usize, key.q_odd as usize, run.session.r_odd() as usize);
            cnt[0][p] += 1;
            cnt[1][q] += 1;
            cnt[2][r] += 1;
            combos[p * 4 + q * 2 + r] += 1;
            n += 1;
            if n >= 32 && combos.iter().all(|c| *c > 0) {
                break;
            }
        }
        for (name, c) in ["P", "Q", "R"].iter().zip(cnt) {
            assert!(c[0] > 0 && c[1] > 0, "{name} parity not covered: {c:?}");
        }
        assert!(combos.iter().all(|c| *c > 0), "not all (P,Q,R) parity combos: {combos:?}");
        eprintln!("ids={:?}: {n} signatures; P even/odd {:?}, Q {:?}, R {:?}; combos {:?}",
                  f.hot_id.serialize()[31], cnt[0], cnt[1], cnt[2], combos);
    }
}

/// With the same nonces and t_path = 0, our δ-split signature is byte-identical
/// to frost-secp256k1-tr's own `sign_with_tweak`/`aggregate_with_tweak(None)`;
/// and the library's per-share z differs from our fragment by exactly λ_h·c·t_eff
/// (the library spreads the tweak over the shares, CHP adds it once at COLD).
#[test]
fn taproot_root_matches_frost_secp256k1_tr_library() {
    use frost_core::round1::Nonce;
    use frost_secp256k1_tr::round1::SigningNonces;
    use frost_secp256k1_tr::{aggregate_with_tweak, round2, SigningPackage};
    let mut rng = rand::thread_rng();
    for ids in id_sets() {
        let f = fixture(ids);
        let key = TaprootKey::derive(KEY_ID, &f.y, "m").unwrap();
        for _ in 0..8 {
            let msg = rand_msg();
            let (n_h, com_h) = presign_nonces(&mut rng);
            let (n_c, com_c) = presign_nonces(&mut rng);
            let (dh, eh) = n_h.to_scalars();
            let (dc, ec) = n_c.to_scalars();
            let lib_nonces = |d: Scalar, e: Scalar| {
                SigningNonces::from_nonces(
                    Nonce::<S>::deserialize(&d.to_repr()).unwrap(),
                    Nonce::<S>::deserialize(&e.to_repr()).unwrap(),
                )
            };
            let (ln_h, ln_c) = (lib_nonces(dh, eh), lib_nonces(dc, ec));
            let mut cm = BTreeMap::new();
            cm.insert(f.hot_id, *ln_h.commitments());
            cm.insert(f.cold_id, *ln_c.commitments());
            let pkg = SigningPackage::new(cm, &msg);
            let zh_lib = round2::sign_with_tweak(&pkg, &ln_h, &f.out.key_packages[&f.hot_id], None).unwrap();
            let zc_lib = round2::sign_with_tweak(&pkg, &ln_c, &f.out.key_packages[&f.cold_id], None).unwrap();
            let mut shares = BTreeMap::new();
            shares.insert(f.hot_id, zh_lib);
            shares.insert(f.cold_id, zc_lib);
            let lib_sig = aggregate_with_tweak(&pkg, &shares, &f.out.public, None).unwrap();
            let lib_sig: [u8; 64] = lib_sig.serialize().unwrap().try_into().unwrap();

            // ours, with δ split
            let (s_prime_h, delta) = split_share(&f.hot.share, &mut rng);
            let sess = Session::new(&key, f.ids, &msg, com_h, com_c).unwrap();
            let z_h = prod_fragment(&sess, SecretNonces::from_scalars(dh, eh).unwrap(), &s_prime_h);
            let sig = cold_complete(&sess, &z_h, n_c, &f.cold.share, &delta, &f.y_h).unwrap();
            assert_eq!(sig, lib_sig, "byte-identical to library");

            // per-share relation: z_h^lib = z_h(δ = 0) + λ_h·c·t_eff
            let z_h_unmasked = prod_fragment(&sess, SecretNonces::from_scalars(dh, eh).unwrap(), &f.hot.share);
            let zh_lib_s = Scalar::from_repr(<[u8; 32]>::try_from(zh_lib.serialize().as_slice()).unwrap().into()).unwrap();
            assert_eq!(zh_lib_s, z_h_unmasked + sess.lambda_h * sess.c * key.t_eff);
            // and our masked fragment differs from the unmasked one by g·λ_h·c·δ
            assert_eq!(z_h - z_h_unmasked, key.g * sess.lambda_h * sess.c * delta);
        }
    }
}

// ---------------------------------------------------------------------------
// Masking identities
// ---------------------------------------------------------------------------

#[test]
fn zero_sum_masking_identity() {
    let mut rng = rand::thread_rng();
    let mut sets: Vec<SignerIds> = id_sets()
        .into_iter()
        .map(|[h, c, _]| {
            SignerIds::new(
                chp_frost::dkg::secp_id(&h).unwrap(),
                chp_frost::dkg::secp_id(&c).unwrap(),
            )
            .unwrap()
        })
        .collect();
    for _ in 0..32 {
        sets.push(SignerIds::new(Scalar::random(&mut rng), Scalar::random(&mut rng)).unwrap());
    }
    for ids in sets {
        let delta = Scalar::random(&mut rng);
        // λ_h·δ + λ_c·(i_c/i_h)·δ = 0
        assert_eq!(ids.lambda_hot() * delta + ids.lambda_cold() * ids.mask_ratio() * delta, Scalar::ZERO);
        assert_eq!(ids.lambda_hot() + ids.lambda_cold(), Scalar::ONE);
        // hence λ_h·s′_h + λ_c·s′_c = λ_h·s_h + λ_c·s_c
        let (s_h, s_c) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
        let s_c_prime = cold_masked_share(&s_c, &delta, &ids);
        assert_eq!(
            ids.lambda_hot() * (s_h + delta) + ids.lambda_cold() * s_c_prime,
            ids.lambda_hot() * s_h + ids.lambda_cold() * s_c
        );
    }
    assert_eq!(SignerIds::new(Scalar::ONE, Scalar::ONE), Err(Error::BadIdentifiers));
    assert_eq!(SignerIds::new(Scalar::ZERO, Scalar::ONE), Err(Error::BadIdentifiers));
}

/// DESIGN SP6 §4.2 / §6 risk: one unused s′_h plus its δ gives HOT's long-term share.
#[test]
fn key_exposure_s_prime_minus_delta_is_s_h() {
    let f = fixture(id_sets()[0]);
    let (s_prime_h, delta) = split_share(&f.hot.share, &mut rand::thread_rng());
    assert_eq!(s_prime_h - delta, f.hot.share);
    // the thief can confirm it against the public share in the manifest
    assert_eq!(ProjectivePoint::GENERATOR * (s_prime_h - delta), f.y_h);
    // and with COLD's share it now has the group secret
    assert_eq!(ProjectivePoint::GENERATOR * group_secret(&f), f.y);
}

// ---------------------------------------------------------------------------
// Negative
// ---------------------------------------------------------------------------

struct Prepared {
    key: TaprootKey,
    msg: [u8; 32],
    sess: Session,
    n_c: (Scalar, Scalar),
    z_h: Scalar,
    delta: Scalar,
}

fn prepare(f: &Fx, path: &str) -> Prepared {
    let mut rng = rand::thread_rng();
    let key = TaprootKey::derive(KEY_ID, &f.y, path).unwrap();
    let msg = rand_msg();
    let (n_h, com_h) = hot_presign_nonces(&mut rng);
    let (n_c, com_c) = presign_nonces(&mut rng);
    let (s_prime_h, delta) = split_share(&f.hot.share, &mut rng);
    let sess = Session::new(&key, f.ids, &msg, com_h, com_c).unwrap();
    let z_h = prod_fragment(&sess, n_h, &s_prime_h);
    Prepared { key, msg, sess, n_c: n_c.to_scalars(), z_h, delta }
}

fn nc(p: &Prepared) -> SecretNonces {
    SecretNonces::from_scalars(p.n_c.0, p.n_c.1).unwrap()
}

#[test]
fn honest_prepared_run_verifies() {
    let f = fixture(id_sets()[2]);
    let p = prepare(&f, "m/0/1");
    let sig = cold_complete(&p.sess, &p.z_h, nc(&p), &f.cold.share, &p.delta, &f.y_h).unwrap();
    assert_valid(&p.key, &p.msg, &sig);
}

#[test]
fn tampered_fragment_is_caught() {
    let f = fixture(id_sets()[0]);
    for path in ["m", "m/5", "m/0/9"] {
        let p = prepare(&f, path);
        let bad = p.z_h + Scalar::ONE;
        assert_eq!(cold_check_fragment(&p.sess, &bad, &f.y_h, &p.delta), Err(Error::FaultProdFragment));
        assert_eq!(
            cold_complete(&p.sess, &bad, nc(&p), &f.cold.share, &p.delta, &f.y_h),
            Err(Error::FaultProdFragment)
        );
        // negated fragment (a sign-convention bug) is also caught
        assert_eq!(cold_check_fragment(&p.sess, &-p.z_h, &f.y_h, &p.delta), Err(Error::FaultProdFragment));
        // even if the check were skipped, the final verification catches it
        let s_c_prime = cold_masked_share(&f.cold.share, &p.delta, &f.ids);
        let sig = cold_combine(&p.sess, &bad, nc(&p), &s_c_prime);
        assert_eq!(verify_bip340(&p.key.q_xonly(), &p.msg, &sig), Err(Error::FaultFinalVerify));
    }
}

#[test]
fn wrong_delta_fails() {
    let f = fixture(id_sets()[1]);
    let p = prepare(&f, "m/1");
    let wrong = p.delta + Scalar::ONE;
    // COLD's Y′_h check fails with the wrong δ
    assert_eq!(cold_check_fragment(&p.sess, &p.z_h, &f.y_h, &wrong), Err(Error::FaultProdFragment));
    assert_eq!(
        cold_complete(&p.sess, &p.z_h, nc(&p), &f.cold.share, &wrong, &f.y_h),
        Err(Error::FaultProdFragment)
    );
    // with the right check but wrong δ in COLD's own share → final verify fails
    let s_c_prime_wrong = cold_masked_share(&f.cold.share, &wrong, &f.ids);
    let sig = cold_combine(&p.sess, &p.z_h, nc(&p), &s_c_prime_wrong);
    assert_eq!(verify_bip340(&p.key.q_xonly(), &p.msg, &sig), Err(Error::FaultFinalVerify));
    // wrong verifying share (REC's instead of HOT's) also fails the check
    assert_eq!(cold_check_fragment(&p.sess, &p.z_h, &f.rec.verifying_share, &p.delta), Err(Error::FaultProdFragment));
}

#[test]
fn fragment_for_different_message_or_path_fails() {
    let f = fixture(id_sets()[0]);
    let mut rng = rand::thread_rng();
    let key = TaprootKey::derive(KEY_ID, &f.y, "m/2").unwrap();
    let (m1, m2) = (rand_msg(), rand_msg());
    let (n_h, com_h) = hot_presign_nonces(&mut rng);
    let (n_c, com_c) = presign_nonces(&mut rng);
    let n_c = n_c.to_scalars();
    let (s_prime_h, delta) = split_share(&f.hot.share, &mut rng);
    // PROD signs m2, COLD completes for m1
    let sess_prod = Session::new(&key, f.ids, &m2, com_h, com_c).unwrap();
    let z_h = prod_fragment(&sess_prod, n_h, &s_prime_h);
    let sess_cold = Session::new(&key, f.ids, &m1, com_h, com_c).unwrap();
    assert_eq!(cold_check_fragment(&sess_cold, &z_h, &f.y_h, &delta), Err(Error::FaultProdFragment));
    let s_c_prime = cold_masked_share(&f.cold.share, &delta, &f.ids);
    let sig = cold_combine(&sess_cold, &z_h, SecretNonces::from_scalars(n_c.0, n_c.1).unwrap(), &s_c_prime);
    assert_eq!(verify_bip340(&key.q_xonly(), &m1, &sig), Err(Error::FaultFinalVerify));
    assert_eq!(verify_bip340(&key.q_xonly(), &m2, &sig), Err(Error::FaultFinalVerify));
    // different path: COLD's session for m/3 rejects a fragment made for m/2
    let key3 = TaprootKey::derive(KEY_ID, &f.y, "m/3").unwrap();
    let sess3 = Session::new(&key3, f.ids, &m2, com_h, com_c).unwrap();
    assert_eq!(cold_check_fragment(&sess3, &z_h, &f.y_h, &delta), Err(Error::FaultProdFragment));
}

#[test]
fn identity_commitments_rejected() {
    let f = fixture(id_sets()[0]);
    let key = TaprootKey::derive(KEY_ID, &f.y, "m").unwrap();
    let (_, com) = presign_nonces(&mut rand::thread_rng());
    let bad = Commitments { hiding: ProjectivePoint::IDENTITY, binding: com.binding };
    assert_eq!(Session::new(&key, f.ids, &[0u8; 32], bad, com).unwrap_err(), Error::IdentityCommitment);
}

// ---------------------------------------------------------------------------
// Nonce reuse (documents the take = delete requirement)
// ---------------------------------------------------------------------------

/// Solve the 3×3 system A·v = z over the scalar field (Cramer's rule).
fn solve3(a: [[Scalar; 3]; 3], z: [Scalar; 3]) -> [Scalar; 3] {
    let det = |m: [[Scalar; 3]; 3]| {
        m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1]) - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
            + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0])
    };
    let d = det(a).invert().unwrap();
    let mut out = [Scalar::ZERO; 3];
    for (col, o) in out.iter_mut().enumerate() {
        let mut m = a;
        for row in 0..3 {
            m[row][col] = z[row];
        }
        *o = det(m) * d;
    }
    out
}

/// If one presignature half (d_h, e_h, s′_h) is used for three different
/// messages, anyone who sees the three fragments (COLD does) solves
///   z_k = g_R,k·d_h + g_R,k·ρ_h,k·e_h + g·λ_h·c_k·s′_h
/// for s′_h; COLD also holds δ, so it obtains s_h = s′_h − δ and, with s_c, the key.
/// (FROST's two-nonce structure means two uses give only a 1-dimensional family;
/// three uses give the share. Two uses are still a break once any third relation leaks.)
#[test]
fn nonce_reuse_leaks_hot_share() {
    let f = fixture(id_sets()[2]);
    let mut rng = rand::thread_rng();
    let key = TaprootKey::derive(KEY_ID, &f.y, "m/7").unwrap();
    let (n_h, com_h) = hot_presign_nonces(&mut rng);
    let (dh, eh) = n_h.to_scalars();
    let (s_prime_h, delta) = split_share(&f.hot.share, &mut rng);
    let mut a = [[Scalar::ZERO; 3]; 3];
    let mut z = [Scalar::ZERO; 3];
    for k in 0..3 {
        // the same half reused (a broken store), fresh COLD commitments each time
        let (_, com_c) = presign_nonces(&mut rng);
        let msg = rand_msg();
        let sess = Session::new(&key, f.ids, &msg, com_h, com_c).unwrap();
        z[k] = prod_fragment(&sess, SecretNonces::from_scalars(dh, eh).unwrap(), &s_prime_h);
        // every fragment individually passes COLD's check — reuse is NOT detected by it
        cold_check_fragment(&sess, &z[k], &f.y_h, &delta).unwrap();
        a[k] = [sess.g_r, sess.g_r * sess.rho_h, key.g * sess.lambda_h * sess.c];
    }
    let [d, e, s_prime] = solve3(a, z);
    assert_eq!((d, e, s_prime), (dh, eh, s_prime_h));
    assert_eq!(s_prime - delta, f.hot.share, "HOT's long-term share recovered");
}

/// Classic single-nonce view: the *final* signatures of a whole reused
/// presignature (same D_h,E_h,D_c,E_c) for the same message are identical,
/// and for k different messages they give k equations in (d_h+d_c, e_h, e_c, x):
/// four uses reveal x itself.
#[test]
fn whole_presignature_reuse_leaks_group_secret_from_public_signatures() {
    let f = fixture(id_sets()[0]);
    let mut rng = rand::thread_rng();
    let key = TaprootKey::derive(KEY_ID, &f.y, "m").unwrap();
    let (n_h, com_h) = hot_presign_nonces(&mut rng);
    let (n_c, com_c) = presign_nonces(&mut rng);
    let (nh, nc_) = (n_h.to_scalars(), n_c.to_scalars());
    let (s_prime_h, delta) = split_share(&f.hot.share, &mut rng);
    // 4 equations: z_k − c_k·t_eff = g_R,k·(d_h + d_c) + g_R,k·ρ_h,k·e_h + g_R,k·ρ_c,k·e_c + c_k·g·x
    let mut rows = Vec::new();
    for _ in 0..4 {
        let msg = rand_msg();
        let sess = Session::new(&key, f.ids, &msg, com_h, com_c).unwrap();
        let z_h = prod_fragment(&sess, SecretNonces::from_scalars(nh.0, nh.1).unwrap(), &s_prime_h);
        let sig = cold_complete(&sess, &z_h, SecretNonces::from_scalars(nc_.0, nc_.1).unwrap(),
                                &f.cold.share, &delta, &f.y_h).unwrap();
        assert_valid(&key, &msg, &sig);
        let z = Scalar::from_repr(<[u8; 32]>::try_from(&sig[32..]).unwrap().into()).unwrap();
        rows.push(([sess.g_r, sess.g_r * sess.rho_h, sess.g_r * sess.rho_c, sess.c * key.g], z - sess.c * key.t_eff));
    }
    // Gaussian elimination on 4×4
    let mut m: Vec<([Scalar; 4], Scalar)> = rows;
    for col in 0..4 {
        let piv = (col..4).find(|r| !bool::from(m[*r].0[col].is_zero())).unwrap();
        m.swap(col, piv);
        let inv = m[col].0[col].invert().unwrap();
        for j in 0..4 {
            m[col].0[j] *= inv;
        }
        m[col].1 *= inv;
        for r in 0..4 {
            if r != col {
                let factor = m[r].0[col];
                let (prow, pz) = m[col];
                for (dst, p) in m[r].0.iter_mut().zip(prow) {
                    *dst -= factor * p;
                }
                m[r].1 -= factor * pz;
            }
        }
    }
    assert_eq!(m[3].1, group_secret(&f), "group secret x recovered from 4 public signatures");
}

// ---------------------------------------------------------------------------
// Library Taproot tweak must not be combined with CHP's t_eff
// ---------------------------------------------------------------------------

#[test]
fn library_tweak_plus_t_eff_double_counts() {
    use frost_secp256k1_tr::keys::Tweak;
    let f = fixture(id_sets()[0]);
    let mut rng = rand::thread_rng();
    for path in ["m", "m/4"] {
        let key = TaprootKey::derive(KEY_ID, &f.y, path).unwrap();
        // (a) PROD fragment computed from a library-tweaked share fails COLD's Y′_h check.
        let tweaked_kp = f.out.key_packages[&f.hot_id].clone().tweak::<&[u8]>(None);
        let s_tw = chp_frost::dkg::secp_party(&tweaked_kp).unwrap().share;
        assert_ne!(s_tw, f.hot.share);
        let (n_h, com_h) = hot_presign_nonces(&mut rng);
        let (n_c, com_c) = presign_nonces(&mut rng);
        let delta = Scalar::random(&mut rng);
        let msg = rand_msg();
        let sess = Session::new(&key, f.ids, &msg, com_h, com_c).unwrap();
        let z_h = prod_fragment(&sess, n_h, &(s_tw + delta));
        assert_eq!(cold_check_fragment(&sess, &z_h, &f.y_h, &delta), Err(Error::FaultProdFragment));
        // (b) and the resulting signature does not verify (tweak counted twice).
        let s_c_tw = chp_frost::dkg::secp_party(
            &f.out.key_packages[&f.cold_id].clone().tweak::<&[u8]>(None)).unwrap().share;
        let s_c_prime = cold_masked_share(&s_c_tw, &delta, &f.ids);
        let sig = cold_combine(&sess, &z_h, n_c, &s_c_prime);
        assert_eq!(verify_bip340(&key.q_xonly(), &msg, &sig), Err(Error::FaultFinalVerify));
    }
}

/// Documents a DESIGN SP2 discrepancy: frost-secp256k1-tr's DKG does NOT output
/// the untweaked Pedersen key. Its `post_dkg` returns
/// `Y_lib = even(Y_raw) + H_TapTweak(Y_raw.x)·G` (and tweaks every share to match).
#[test]
fn frost_tr_dkg_output_is_already_bip86_tweaked() {
    let f = fixture(id_sets()[0]);
    let y_raw = f
        .out
        .constant_term_commitments
        .iter()
        .map(|b| chp_frost::dkg::secp_point(b).unwrap())
        .fold(ProjectivePoint::IDENTITY, |a, p| a + p);
    assert_ne!(y_raw, f.y);
    let bip86_of_raw = TaprootKey::from_internal_key(&y_raw).unwrap();
    assert_eq!(bip86_of_raw.q, f.y, "Y_lib = BIP86 output key of the raw Pedersen key");
    // So CHP's root address is BIP86(BIP86(Y_raw)) when built on this library.
    let root = TaprootKey::derive(KEY_ID, &f.y, "m").unwrap();
    assert_ne!(root.q_xonly(), bip86_of_raw.q_xonly());
}
