//! Official test vectors: BIP340, BIP86, BIP341, plus CHP `t_path` known answers.

use chp_frost::derive::{t_path_ed25519, t_path_secp256k1};
use chp_frost::hash::bip340_tagged_hash;
use chp_frost::secp::{bip340_challenge, verify_bip340};
use chp_frost::taproot::{has_odd_y, lift_x, sign_factor, tap_tweak, x_only, TaprootKey};
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar};

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn h32_slice(b: &[u8]) -> [u8; 32] {
    b.try_into().unwrap()
}

// ---------------------------------------------------------------------------
// BIP340
// ---------------------------------------------------------------------------

/// All rows of bip-0340/test-vectors.csv
/// (https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv, fetched 2026-11-03).
/// (index, secret key, public key, aux_rand, message, signature, verification result)
const BIP340_VECTORS: &[(u32, &str, &str, &str, &str, &str, bool)] = &[
    (0, "0000000000000000000000000000000000000000000000000000000000000003", "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0", true),
    (1, "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "0000000000000000000000000000000000000000000000000000000000000001", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A", true),
    (2, "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9", "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8", "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906", "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C", "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7", true),
    (3, "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710", "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3", true),
    (4, "", "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9", "", "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703", "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4", true),
    (5, "", "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false),
    (6, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2", false),
    (7, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD", false),
    (8, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6", false),
    (9, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051", false),
    (10, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197", false),
    (11, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false),
    (12, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false),
    (13, "", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", false),
    (14, "", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30", "", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", false),
    (15, "0340034003400340034003400340034003400340034003400340034003400340", "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "0000000000000000000000000000000000000000000000000000000000000000", "", "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63", true),
    (16, "0340034003400340034003400340034003400340034003400340034003400340", "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "0000000000000000000000000000000000000000000000000000000000000000", "11", "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF", true),
    (17, "0340034003400340034003400340034003400340034003400340034003400340", "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "0000000000000000000000000000000000000000000000000000000000000000", "0102030405060708090A0B0C0D0E0F1011", "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5", true),
    (18, "0340034003400340034003400340034003400340034003400340034003400340", "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", "0000000000000000000000000000000000000000000000000000000000000000", "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999", "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367", true),
];

/// BIP340 `Verify` written against this crate's challenge, lift_x and parity
/// helpers (the same helpers the split signer uses), on k256 arithmetic.
fn own_bip340_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Some(p) = lift_x(pk) else { return false };
    let r_x: [u8; 32] = sig[..32].try_into().unwrap();
    // r < p (field) is implied by lift_x succeeding on r below; s < n:
    let Some(s) = Option::<Scalar>::from(Scalar::from_repr(h32_slice(&sig[32..]).into())) else {
        return false;
    };
    if lift_x(&r_x).is_none() {
        // r is not an x coordinate on the curve (or ≥ p)
        return false;
    }
    let e = bip340_challenge(&r_x, pk, msg);
    let r = ProjectivePoint::GENERATOR * s - p * e;
    if bool::from(k256::elliptic_curve::group::Group::is_identity(&r)) {
        return false;
    }
    !has_odd_y(&r) && x_only(&r) == r_x
}

/// BIP340 reference `Sign`, using this crate's tagged hash, challenge and
/// sign-factor helpers. The two negations here (secret key by g_P, nonce by g_R)
/// are exactly the sign factors the split signer applies.
fn own_bip340_sign(sk: &[u8; 32], msg: &[u8], aux: &[u8; 32]) -> [u8; 64] {
    let d0 = Scalar::from_repr((*sk).into()).unwrap();
    let p = ProjectivePoint::GENERATOR * d0;
    let d = d0 * sign_factor(has_odd_y(&p)); // g_P·d0
    let aux_h = bip340_tagged_hash("BIP0340/aux", &[aux]);
    let d_bytes: [u8; 32] = d.to_repr().into();
    let mut t = [0u8; 32];
    for i in 0..32 {
        t[i] = d_bytes[i] ^ aux_h[i];
    }
    let rand = bip340_tagged_hash("BIP0340/nonce", &[&t, &x_only(&p), msg]);
    let k0 = <Scalar as k256::elliptic_curve::ops::Reduce<k256::U256>>::reduce_bytes(&rand.into());
    assert!(!bool::from(k256::elliptic_curve::Field::is_zero(&k0)));
    let r = ProjectivePoint::GENERATOR * k0;
    let k = k0 * sign_factor(has_odd_y(&r)); // g_R·k0
    let e = bip340_challenge(&x_only(&r), &x_only(&p), msg);
    let s = k + e * d;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&x_only(&r));
    sig[32..].copy_from_slice(&s.to_repr());
    assert!(own_bip340_verify(&x_only(&p), msg, &sig));
    sig
}

#[test]
fn bip340_vectors_verify_with_libsecp256k1_and_own_verifier() {
    for (idx, _sk, pk, _aux, msg, sig, expected) in BIP340_VECTORS {
        let pk = h32(pk);
        let msg = hex::decode(msg).unwrap();
        let sig: [u8; 64] = hex::decode(sig).unwrap().try_into().unwrap();
        let lib = verify_bip340(&pk, &msg, &sig).is_ok();
        assert_eq!(lib, *expected, "libsecp256k1 disagrees on vector {idx}");
        let own = own_bip340_verify(&pk, &msg, &sig);
        assert_eq!(own, *expected, "own verifier disagrees on vector {idx}");
    }
}

#[test]
fn bip340_vectors_sign_reproduces_signatures() {
    let mut n = 0;
    for (idx, sk, pk, aux, msg, sig, _) in BIP340_VECTORS {
        if sk.is_empty() {
            continue;
        }
        let sk = h32(sk);
        let p = ProjectivePoint::GENERATOR * Scalar::from_repr(sk.into()).unwrap();
        assert_eq!(x_only(&p), h32(pk), "public key mismatch vector {idx}");
        let got = own_bip340_sign(&sk, &hex::decode(msg).unwrap(), &h32(aux));
        assert_eq!(hex::encode_upper(got), *sig, "signature mismatch vector {idx}");
        n += 1;
    }
    assert_eq!(n, 8);
}

/// Vectors 1 and 2 have odd-y P (so g_P = −1 is exercised by the reference signer).
#[test]
fn bip340_vectors_cover_odd_public_keys() {
    let mut odd = 0;
    for (_, sk, ..) in BIP340_VECTORS {
        if sk.is_empty() {
            continue;
        }
        let p = ProjectivePoint::GENERATOR * Scalar::from_repr(h32(sk).into()).unwrap();
        odd += has_odd_y(&p) as u32;
    }
    assert!(odd >= 1);
}

// ---------------------------------------------------------------------------
// BIP86 / BIP341
// ---------------------------------------------------------------------------

/// BIP86 test vectors, https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
/// ("Test vectors", mnemonic "abandon … about"): m/86'/0'/0'/0/0, m/86'/0'/0'/0/1, m/86'/0'/0'/1/0.
/// (internal_key, output_key, address)
const BIP86_VECTORS: &[(&str, &str, &str)] = &[
    (
        "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
        "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
    ),
    (
        "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145",
        "a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb",
        "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
    ),
    (
        "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef",
        "882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc",
        "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
    ),
];

#[test]
fn bip86_output_keys_and_addresses() {
    for (internal, output, addr) in BIP86_VECTORS {
        let p = lift_x(&h32(internal)).unwrap();
        let k = TaprootKey::from_internal_key(&p).unwrap();
        assert_eq!(hex::encode(k.q_xonly()), *output);
        assert_eq!(k.bip86_address("bc"), *addr);
    }
}

/// BIP341 wallet-test-vectors.json, scriptPubKey[0] (key path only, scriptTree = null):
/// https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json
#[test]
fn bip341_keypath_only_vector() {
    let internal = h32("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d");
    let t = tap_tweak(&internal).unwrap();
    assert_eq!(
        hex::encode(t.to_repr()),
        "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70"
    );
    let k = TaprootKey::from_internal_key(&lift_x(&internal).unwrap()).unwrap();
    assert_eq!(
        hex::encode(k.q_xonly()),
        "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"
    );
    assert_eq!(
        hex::encode(k.script_pubkey()),
        "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"
    );
    assert_eq!(k.bip86_address("bc"), "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5");
}

/// Independent check of Q and its parity against libsecp256k1's x-only tweak,
/// for random (possibly odd-y) internal keys P.
#[test]
fn taproot_output_key_matches_libsecp256k1_tweak_add() {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let (mut odd_p, mut odd_q) = (0, 0);
    for _ in 0..200 {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        let sk = Scalar::from_repr(b.into()).unwrap();
        let p = ProjectivePoint::GENERATOR * sk;
        let k = TaprootKey::from_internal_key(&p).unwrap();
        odd_p += k.p_odd as u32;
        odd_q += k.q_odd as u32;
        let xpk = secp256k1::XOnlyPublicKey::from_byte_array(&k.p_xonly()).unwrap();
        let tweak = secp256k1::Scalar::from_be_bytes(k.t_tap.to_repr().into()).unwrap();
        let (q, parity) = xpk.add_tweak(secp256k1::SECP256K1, &tweak).unwrap();
        assert_eq!(q.serialize(), k.q_xonly());
        assert_eq!(parity == secp256k1::Parity::Odd, k.q_odd);
        // Invariant on public values: (g_P·P + t_tap·G)·g_Q is even-y Q.
        assert!(!has_odd_y(&k.q_even()));
    }
    assert!(odd_p > 0 && odd_q > 0);
}

// ---------------------------------------------------------------------------
// t_path known answers (computed independently with Python hashlib; see REVIEW.md)
// ---------------------------------------------------------------------------

#[test]
fn t_path_known_answers() {
    // secp256k1, Y = G (compressed), key_id = "key-1", path = "m/0/7"
    let g = chp_frost::derive::sec1_compressed(&ProjectivePoint::GENERATOR);
    let t = t_path_secp256k1(b"key-1", &g, "m/0/7");
    assert_eq!(
        hex::encode(t.to_repr()),
        "c24f85b384b1c46ac1c163505c483d5d3927417905f1f591a877330627e00171"
    );
    // root path is zero
    assert_eq!(t_path_secp256k1(b"key-1", &g, "m"), Scalar::ZERO);
    // Ed25519, Y = basepoint, same key_id/path: SHA-512 framing, wide reduction (LE output)
    let b = curve25519_dalek::constants::ED25519_BASEPOINT_POINT.compress().to_bytes();
    assert_eq!(
        hex::encode(t_path_ed25519(b"key-1", &b, "m/0/7").to_bytes()),
        "1aeeb8183f354335d40ee51b28059cea053f1985fb9adafc25955971500e0208"
    );
    assert_eq!(t_path_ed25519(b"key-1", &b, "m"), curve25519_dalek::Scalar::ZERO);
    // framing: moving a byte between fields changes the hash
    assert_ne!(
        t_path_secp256k1(b"key-1", &g, "m/0/7"),
        t_path_secp256k1(b"key-", &g, "1m/0/7")
    );
}
