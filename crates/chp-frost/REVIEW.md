# chp-frost — validation notes for DESIGN SP6 §4.2 (Schnorr / FROST split signing)

Status: prototype / reference implementation. `cargo test -p chp-frost` → 29 tests, all green;
`cargo clippy -p chp-frost --all-targets` clean.

This document lists what was validated, every formula exactly as implemented, the
discrepancies and ambiguities found in DESIGN (SP2, SP5 step 1, SP6 §4, §4.2, SP10), and
what still needs independent review.

---

## 1. What was validated

| # | Claim | Evidence (test) |
|---|---|---|
| 1 | BIP340 challenge / lift_x / parity helpers are correct | all 19 rows of `bip-0340/test-vectors.csv` verified with **libsecp256k1** and with an own verifier built on this crate's `bip340_challenge`, `lift_x`, `has_odd_y` (`vectors::bip340_vectors_verify_*`) |
| 2 | Sign-factor handling (`g_P` on the key, `g_R` on the nonce) matches BIP340 | a reference BIP340 signer built on the same helpers reproduces all 8 signing vectors **byte for byte** (`bip340_vectors_sign_reproduces_signatures`; vectors 1/2 have odd-y P) |
| 3 | `t_tap`, `Q`, address encoding | BIP86 vectors (3 internal→output keys + bech32m addresses) and BIP341 `wallet-test-vectors.json` scriptPubKey[0] (tweak, tweaked key, scriptPubKey, address) |
| 4 | `Q` and `g_Q` are right for random odd/even `P` | 200 random keys cross-checked against libsecp256k1 `XOnlyPublicKey::add_tweak` (x and parity) |
| 5 | `t_path` framing | known answers computed independently with Python `hashlib` (secp256k1 and Ed25519); root → 0 |
| 6 | Signing-key invariant `(g·x + t_eff)·G = g_Q·Q` | 64 paths, `x` reconstructed by Lagrange (`taproot_signing_key_invariant`) |
| 7 | Full flow DKG → presign → split → PROD fragment → COLD check → COLD complete → independent verify | Taproot root path; Taproot ≥ 32 random paths **per identifier set until all 8 parity combinations of (P, Q, R) occurred** (counts asserted, printed with `--nocapture`); Ed25519 with messages of length 0/1/32/200. Verifiers: libsecp256k1 + k256 (Taproot), ed25519-dalek `verify_strict` + frost-ed25519 (Ed25519) |
| 8 | Identifier handling | every flow runs with identifiers (HOT,COLD,REC) = (1,2,3), (3,1,2) (i.e. `i_h > i_c`) and `Identifier::derive("HOT"/"COLD"/"REC")` (hash-derived scalars) |
| 9 | Our math is *exactly* RFC 9591 FROST | with identical nonces, the δ-split signature is **byte-identical** to frost-secp256k1-tr `sign_with_tweak`+`aggregate_with_tweak(None)` (root path) and to frost-ed25519 `sign`+`aggregate`. Also per share: `z_h^lib = z_h(δ=0) + λ_h·c·t_eff` (Taproot) / `z_h^lib = z_h(δ=0)` (Ed25519), and `z_h − z_h(δ=0) = g·λ_h·c·δ` |
| 10 | Zero-sum masking `λ_h·δ + λ_c·(i_c/i_h)·δ = 0`, `λ_h + λ_c = 1` | DKG identifiers + 32 random identifier pairs |
| 11 | Negatives | tampered `z_h` (and `−z_h`) → `FAULT_PROD_FRAGMENT`; same with the check bypassed → `FAULT_FINAL_VERIFY`; wrong `δ` → check fails, and wrong `δ` only in `s′_c` → final verify fails; fragment for another message or another path → check fails, bypassed → final verify fails for both messages; wrong `Y_h` (REC's) → check fails; identity commitments rejected |
| 12 | Nonce reuse leaks keys (take = delete) | 3 fragments from one reused half → `s′_h` by linear algebra → `s_h = s′_h − δ` (COLD holds δ). 4 *public* signatures from one fully reused presignature → group secret `x` |
| 13 | Key exposure (DESIGN §4.2 ⚠) | `s′_h − δ = s_h`, confirmable against public `Y_h` |
| 14 | Library Taproot tweak must not be combined | fragment from a library-tweaked share fails COLD's `Y′_h` check; signature with library-tweaked shares **plus** `c·t_eff` fails verification |
| 15 | frost-secp256k1-tr DKG output is already BIP86-tweaked (discrepancy D1) | `Y_lib = BIP86(Σ a_{i0}·G)` asserted |

---

## 2. Formulas as implemented

### 2.1 Hashes (`hash.rs`)

```
tagged_hash(tag, fields)     = SHA-256( u32_be(|tag|) ‖ tag ‖ Π_f ( u32_be(|f|) ‖ f ) )
tagged_hash_512(tag, fields) = SHA-512( same framing )
bip340_tagged_hash(tag, x)   = SHA-256( SHA-256(tag) ‖ SHA-256(tag) ‖ x )        (Bitcoin framing)
```

### 2.2 `t_path` (`derive.rs`)

```
path == "m"  →  t_path = 0
secp256k1:  t_path = int_be( tagged_hash("chp-derive-v1", [key_id, SEC1_compressed(Y) (33 B), utf8(path)]) ) mod n
Ed25519:    t_path = from_bytes_mod_order_wide( tagged_hash_512("chp-derive-v1", [key_id, enc(Y) (32 B), utf8(path)]) )
P = Y + t_path·G
```

Choice for Ed25519: SHA-512 with the *same framing*, wide-reduced, because a 256-bit
digest mod ℓ ≈ 2²⁵² is visibly biased. Ed25519 only uses the root, so this is fixed
for the future rather than used today. KAT (key_id = "key-1", path = "m/0/7"):
secp256k1, `Y = G`: `t = c24f85b3…27e00171`; Ed25519, `Y = B`: `t(LE) = 1aeeb818…500e0208`
(full values in `tests/vectors.rs`). **The other crate implementing `t_path` must
reproduce these.**

### 2.3 Taproot key (`taproot.rs`) — as SP6 §4.2, no changes

```
P     = Y + t_path·G
g_P   = +1 if P.y even else −1
t_tap = int( hash_TapTweak(P.x) )           fail if ≥ n   (BIP341; (g_P·P).x = P.x)
Q     = g_P·P + t_tap·G
g_Q   = +1 if Q.y even else −1
g     = g_Q·g_P
t_eff = g_Q·(g_P·t_path + t_tap)
```

### 2.4 Session (`secp.rs`, `ed25519.rs`)

```
λ_h = i_c/(i_c − i_h)        λ_c = i_h/(i_h − i_c)      (i = frost-core identifier *scalar*)
prefix = ser(Y_p) ‖ H4(m) ‖ H5( Π_{j sorted by i_j} ser(i_j) ‖ ser(D_j) ‖ ser(E_j) )
ρ_j    = H1( prefix ‖ ser(i_j) )
R      = D_h + ρ_h·E_h + D_c + ρ_c·E_c        (reject identity commitments and R = O)
```

| | Taproot (`FROST-secp256k1-SHA256-TR-v1`) | Ed25519 (`FROST-ED25519-SHA512-v1`) |
|---|---|---|
| `ser(Y_p)` | **`0x02 ‖ Q.x`** (SEC1 of `g_Q·Q`) | 32-byte `enc(Y)` |
| `ser(i)` | 32-byte big-endian | 32-byte little-endian |
| `ser(point)` | 33-byte SEC1 compressed | 32-byte RFC 8032 |
| `H1` | `hash_to_field`, `expand_message_xmd(SHA-256)`, DST = ctx‖"rho" | `SHA-512(ctx‖"rho"‖x) mod ℓ` (wide) |
| `H4`, `H5` | `SHA-256(ctx‖"msg"‖x)`, `SHA-256(ctx‖"com"‖x)` | `SHA-512(ctx‖"msg"‖x)`, `SHA-512(ctx‖"com"‖x)` |
| `g_R` | `+1` if `R.y` even else `−1` | 1 |
| `c` | `int(hash_BIP0340/challenge(R.x ‖ Q.x ‖ m)) mod n` | `SHA-512(enc(R) ‖ enc(Y) ‖ m) mod ℓ` |
| `g`, `t_eff` | §2.3 | 1, 0 |

### 2.5 PROD / COLD

```
HOT  (SP5 step 1):  δ ←$ Z_q \ {0};  s′_h = s_h + δ          s′_h → PROD, δ → COLD
PROD:               z_h = g_R·(d_h + e_h·ρ_h) + g·λ_h·s′_h·c
COLD check:         z_h·G == g_R·(D_h + ρ_h·E_h) + g·λ_h·c·Y′_h,   Y′_h = Y_h + δ·G
COLD:               s′_c = s_c + (i_c/i_h)·δ
                    z_c  = g_R·(d_c + e_c·ρ_c) + g·λ_c·s′_c·c
                    z    = z_h + z_c + c·t_eff
signature:          Taproot  R.x ‖ int_be(z)  (64 B)     Ed25519  enc(R) ‖ int_le(z)  (64 B)
verify:             libsecp256k1 schnorr verify vs Q.x  /  ed25519-dalek verify_strict vs Y
```

---

## 3. Discrepancies and ambiguities in DESIGN

**D1 — SP2 "DKG outputs the untweaked group key Y" is false with frost-secp256k1-tr 3.0 (real discrepancy).**
`frost_secp256k1_tr::Secp256K1Sha256TR::post_dkg` runs inside `dkg::part3` and returns
`Y_lib = g(Y_raw)·Y_raw + int(hash_TapTweak(Y_raw.x))·G`, where `Y_raw = Σ a_{i0}·G` and `g(Y_raw)` is the
even-y sign factor. Every signing share and verifying share is tweaked the same way. That is
still a valid 2-of-3 Shamir sharing, so all SP6 algebra holds with `Y := Y_lib` (tested end to
end). But:
- the `Y` in the KeyManifest, in fingerprints and in `t_path` is `Y_lib`, not the Pedersen sum;
- CHP's root address is `BIP86(Y_lib) = BIP86(BIP86(Y_raw))`. Nobody can reproduce it from `Y_raw`;
- every component that computes `Y` (ceremony, COLD, PROD, SP10 verifiers) must use the same
  library or reimplement `post_dkg`. Mixing in a `frost-secp256k1` (non-TR) DKG or a raw sum gives a different key.

Proposed DESIGN text: *"Taproot: the group key `Y` is the key output by the FROST-secp256k1-TR
DKG, which the library already tweaks (`post_dkg`: even-y lift plus TapTweak with an empty
merkle root). CHP treats this output as its untweaked `Y` and applies its own per-path
derivation and BIP86 tweak on top."* The alternative is a frost-core DKG with a ciphersuite
that has no `post_dkg`. The extra library tweak is harmless and keeps the library's
protection against a rogue script commitment in `Y`, so keeping it is recommended.

**D2 — Encoding of `Y_p` in the binding factor (ambiguity).** SP6 writes `ρ_j = H₁(Y_p, m, B, j)`
with `Y_p = Q`, but `Q` can have odd y, and it does not say whether `ser(Q)` or the even lift goes
into H₁. This crate uses `ser(g_Q·Q) = 0x02‖Q.x`. That matches frost-secp256k1-tr, whose `pre_sign`
lifts the key package to even y before computing binding factors. Byte equality with the library
is tested. Recommend writing it into SP6 as `ser(Y_p) := 0x02 ‖ Q.x`.

**D3 — Identifiers in λ and in `i_c/i_h` (clarification).** `i_h`, `i_c` must be the frost-core
identifier *scalars*. They equal 1, 2, 3 only for `Identifier::try_from(u16)`.
`Identifier::derive(..)` gives hash scalars, and Ed25519 serialises identifiers little-endian.
All three cases are tested. The commitment list `B` is sorted by identifier as an integer.
SP2 never fixes which identifier each party gets. Recommend recording the identifier per party
in the `KeyManifest`, because λ and the mask ratio depend on it.

**D4 — COLD's check equation and sign conventions hold exactly as written (no correction).**
`z_h·G = g_R·(D_h + ρ_h·E_h) + g·λ_h·c·Y′_h` holds in all 8 parity combinations of (P, Q, R). So do
`z = z_h + z_c + c·t_eff` and `(g·x + t_eff)·G = g_Q·Q`. "signature = (g_R·R, z)" is fine:
BIP340 serialises only `R.x`, and Ed25519 has `g_R = 1`. Relation to the library: the library
adds the tweak to every share (`Σλ = 1`), CHP adds `c·t_eff` once at COLD; per share,
`z_h^lib = z_h^CHP(δ=0) + λ_h·c·t_eff`.

**D5 — Nonce reuse: "two signatures leak the key" is not quite right for FROST; the real exposure is via COLD.**
With two nonces per signer, each reuse of a half gives one linear equation in
`(d_h, e_h, s′_h)`. Because ρ depends on m and B, **three** fragments from one reused half
determine `s′_h`, and COLD holds δ, so COLD (or anyone holding COLD's state) gets `s_h` and,
with `s_c`, the key. Two uses leave a one-dimensional family, which is not safe either.
**COLD's fragment check does not detect reuse**: every reused fragment passes. So the defences
are exactly SP6 step 3 and step 4 (take = delete, monotonic high-water mark), and COLD must never
complete a `presig_id` twice. From public signatures alone, a fully reused presignature (both
halves) used for four messages gives `x` (tested).

**D6 — BIP341 `t_tap ≥ n` (minor omission).** BIP341 says to fail. DESIGN is silent. The crate returns
`TweakOutOfRange` (probability ≈ 2⁻¹²⁸). The same applies to `P = O` or `Q = O`
(`InfinityKey`). Recommend: if derivation fails, the address entry cannot exist.

**D7 — Path syntax (ambiguity).** `t_path` hashes the raw UTF-8 bytes of `path`, and only the
exact string `"m"` is the root. DESIGN does not define path syntax or canonical form (for example
`"m/0"` vs `"m/00"` vs `"m/0/"`). Each of these is a *different key*. Recommend a grammar (for example
`m(/[0-9]+)*`, no leading zeros) checked at AddressBook signing and at admission.

**D8 — SP2 test signatures "verified against Y" (ambiguity for Taproot).** A Taproot signature
under this scheme verifies against `Q`, not `Y`. Recommend "verified against `Y_p` of the root path".
For BIP340 against `Y` itself, a plain FROST-TR signature with the library is enough.

**D9 — The binding factor does not cover ssid / presig_id.** It covers exactly RFC 9591's
inputs: `Y_p` (which binds the path), `m`, and `B`. Everything else in the ssid is bound outside
the signature (Job AAD, COLD's checks). RFC 9591 allows no additional prefix. That is fine,
but worth noting for review.

---

## 4. Remaining items for independent review

1. The δ-split construction itself (DESIGN ⚠): its security argument, especially that `z_h` together with the per-presignature `s′_h` held by PROD leaks nothing beyond plain FROST to PROD, and that COLD learns nothing about `s_h` from one honest fragment (it gets one equation with fresh unknown nonces).
2. The Taproot sign factors (`g_P`, `g_Q`, `g`, `g_R`, `t_eff`) and `t_path` as a non-BIP32 additive derivation. Related-key concerns: the same nonce must never be used under two paths, and SP4 already binds presignatures to a path.
3. D1 decision: keep the frost-secp256k1-tr `post_dkg` tweak (recommended) or replace it.
4. Zeroization: `SecretNonces`, `s′_h`, `δ` and `s_c` are plain values here (prototype). The production engines must zeroize them and keep δ inside COLD's TEE/HSM.
5. Constant time: `k256` and `curve25519-dalek` arithmetic is constant time. The final verification and the fragment check run on public data. Not audited.
6. `verify_strict` vs chain rules: Ed25519 chains differ (cofactored vs cofactorless). Honest FROST signatures pass both, but confirm each target chain's verifier.
7. `t_path` agreement with `crates/chp-crypto`: by inspection, `chp-crypto/src/{hash,derive}.rs` uses the same framing, tag, inputs and reduction for secp256k1. It has no Ed25519 variant. Recommend that `chp-crypto` add the KAT from `tests/vectors.rs::t_path_known_answers`, or that the engines call one implementation, so the two cannot drift apart.
