# Design notes from the prototype

Findings while implementing [`DESIGN.md`](DESIGN.md): ambiguities, choices the prototype made, and
proposed design changes. Status: prototype as of 2026-11-03.

## A. Cryptography

| # | Finding | Status |
|---|---|---|
| A1 | **DKLs23 split works as specified.** The library's presign output is exactly `(sid, R, φ_i, s₀′_i, s₁_i)`. Presigning at the library root path and applying CHP's `m + r·t` at fragment time gives valid signatures for derived keys. Verified with libsecp256k1 (`crates/chp-mpc/tests/ecdsa_split.rs`) | validated |
| A2 | **Key-equivalence of both halves** (`x = Σs₀′ / (r·Σφ)`, DESIGN §6) reproduced as a regression test. **Nonce reuse** of one presignature for two messages reveals `x` (tested), which is why take = delete and the per-pool counter are mandatory | validated |
| A3 | **Refresh** (DKLs23 key refresh): same `Y`, every share changes, every pair of new shares signs, old + new shares fail at presign (library consistency check) | validated (library level; SP8 ceremony not yet wired into engines) |
| A4 | **FROST δ masking and Taproot sign factors**: algebra holds exactly as written in SP6 §4.2, across all odd/even-y cases for `P`, `Q` and `R`; it reproduces the official BIP340/BIP86/BIP341 vectors and is byte-identical to frost-secp256k1-tr / frost-ed25519 at the root path. Details: [`crates/chp-frost/REVIEW.md`](../crates/chp-frost/REVIEW.md) | validated, still needs independent review |
| A5 | **D1, a real discrepancy**: frost-secp256k1-tr's DKG already applies an even-y lift and BIP86 TapTweak (`post_dkg`), so its `Y` is not the "untweaked" Pedersen sum SP2 describes. Proposal: define `Y` as the library's DKG output, or use a ciphersuite without `post_dkg` | design text to change |
| A6 | **D2**: the encoding of `Y_p` in the FROST binding factor ρ when `Q` has odd y must be pinned (prototype: `0x02 ‖ Q.x`, matches the library) | design text to add |
| A7 | **D3**: `λ` and `i_c/i_h` use frost-core identifier scalars. The manifest should record each party's FROST identifier | add field to `KeyManifest` |
| A8 | **D5**: with FROST's two nonces, **3** fragments from one reused half give `s′_h` (then `s_h` with COLD's δ); COLD's fragment check does not detect reuse. Only take = delete and the high-water mark defend against it | note in SP6 |
| A9 | **D6–D9**: fail if `t_tap ≥ n` (BIP341); define a path grammar (`"m/0"` ≠ `"m/00"` today); SP2's "test signature verified against Y" should say root-path `Y_p` for Taproot; ρ does not bind ssid/presig id (consistent with RFC 9591) | minor |

## B. Protocol choices the prototype made

| # | Topic | DESIGN says | Prototype does | Proposal |
|---|---|---|---|---|
| B1 | **Trusted time** (§9.3) | two independent signed time sources, but no message carries them | `WithdrawalEnvelope.upstream_time` (UPSTREAM-signed) and `Job.prod_time` (PROD-signed); COLD rejects if they differ by more than `max_time_skew` and uses `max(local floor, prod_time)` for expiry | add both fields to SP6 |
| B2 | **Which pool a job burns** | "advance the pool's high-water mark, then take every named half" before re-verification | the pool is `(envelope.key_id, job.key_version, envelope.path)` read from the **not yet verified** envelope. A hostile PROD can therefore choose which pool's halves get burned, which it could do anyway by consuming them | state this explicitly in SP6 step 4.3 |
| B3 | **Discard floor** after a detected restore | "every id up to the pool's current block is refused" | the floor is the **highest issued block** (≥ current block): batches allocated in future blocks before the restore are also distrusted | clarify in §6.1 |
| B4 | `PoolStatus` | carries `available` (count) | carries the list of available ids; reconciliation needs ids | change the field |
| B5 | `OrphanDelete.up_to_block` | "all ids up to the closed block" | deletes ids in blocks **strictly below** `up_to_block` (the new counter value) | define the bound precisely |
| B6 | Revocation of an unlinked party | "if the revoked party is HOT, COLD or PROD, every pool is discarded" | a `RevocationList` names only `SHA-256(id_pk)`; COLD can't tell an unlinked HOT/PROD key from a quorum member's, so it discards conservatively on any non-client revocation | add `role` to each revoked entry |
| B7 | Job idempotency | look up `job_seq` | `job_seq` is PROD's own counter, persistent across links; identical body → stored `Status`, different body → refused | ok as designed |
| B8 | DKLs23 message authentication | every message signed | library-level signing disabled (`NoSigningKey`); each library message travels in a CHP `SignedMsg` (`PresignMsg`) checked by the SP1 frame checker first | ok, document |
| B9 | Ceremony network | signed protocol messages after cross-attestation | in-process mesh (`chp_mpc::dkls::local_mesh`) without CHP framing | prototype simplification |
| B10 | HOT presign rate limit inside a window | required | not implemented (window batch cap only) | prototype gap |

## C. Not yet implemented (see PLAN.md status)

- SP8 refresh as an engine-level ceremony (library refresh validated, A3), PROD replacement flow.
- SP9 QR transport.
- FROST engines (crypto validated in `chp-frost`, not wired into HOT/COLD/PROD).
- High-security mode `Dkg` return stage (refused correctly; the in-window DKG continuation is not wired).
- Hash-chained audit log export (events are recorded in memory per engine).

## D. Found by the demo (`cargo run -p chp-sim --example demo`)

| # | Finding | Fix in the prototype | Proposal |
|---|---|---|---|
| B11 | **`job_seq` collides across a PROD replacement.** SP6 step 4.2 looks up `job_seq` alone. A new PROD restarts at 1, so COLD refused its first job as "job_seq reused with different content" | COLD keys its job table by `(PROD signer, job_seq)` | SP6: idempotency key is `(PROD identity, job_seq)`, or the quorum assigns each PROD a `job_seq` floor |
| B12 | Revocation at PROD discarded pools for any non-client key (B6 again, at PROD) | PROD discards only if the revoked key is its COLD peer, itself, or a HOT that signed an imported bundle | same as B6: put `role` in revocation entries |

## E. From the security review ([`SECURITY.md`](SECURITY.md))

Design-level changes the prototype adopted:

| # | DESIGN says | Proposal (implemented in the prototype) |
|---|---|---|
| E1 | §6.1 protects presignature pools against storage restore | Protect **all** of COLD's control state (freeze, revocation, rosters, policy, ledger, replay cache). Use a `state` hardware counter advanced on every control change and at boot, and fail closed on a detected restore |
| E2 | `Unfreeze{key_id, key_version, version}` | Add `evidence_hash` of the freeze being lifted, so a withheld Unfreeze cannot lift a later freeze |
| E3 | SP10 verification checks the proof | Also check that the proof answers the query asked (chain, address/path, `request_id`) |
| E4 | Policy content is the deployer's | State that fees move funds (`gas_limit · max_fee` capped and counted in limits) and that limits use a rolling window |
| E5 | SP4 PresignOpen checks | HOT also checks that the key/version equal the agreed wake window's |
| E6 | Revocation by `SHA-256(id_pk)` | Include the role (B6/B12 again): parties cannot tell an unlinked HOT/COLD/PROD key from others |
| E7 | Certificates short-lived | Re-check validity at every use, not only at handshake/enrollment |
