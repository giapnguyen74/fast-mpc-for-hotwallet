# Security review

Internal review of the prototype, 2026-11-03. Three independent reviewers covered:

1. COLD's signing path (everything a compromised PROD can send, plus policy, chain decoding and anti-rollback);
2. authentication, wire format, HOT, PROD, media transfer and address proofs;
3. cryptography and the MPC bridge.

A dependency audit (`cargo audit`) ran alongside. Every finding was checked against the code
before it was fixed, and each fix has a regression test where one is practical.

> This is not an independent audit. The prototype is not production software: see the README
> warnings and DESIGN §6.3. The REVIEW REQUIRED constructions (FROST δ masking, Taproot sign
> factors, `t_path`) still need external cryptographic review.

## What held up

- **No signature without UPSTREAM.** A fully compromised PROD could not obtain a signature for
  anything UPSTREAM did not sign. Swapped envelopes, fragments for other messages or paths,
  ssid mismatches and tampered ciphertexts are all refused, or freeze the key.
- **No presignature reuse.** Halves are deleted before compute, the high-water mark and per-pool
  hardware counters hold, and restore detection works for consumed blocks.
- **No leak of COLD's half or share** through any protocol message.
- **Signing math is correct:**
  - ECDSA `m + r·t`, low-s and the recovery id;
  - the FROST sign factors and δ masking;
  - strict verifiers (libsecp256k1 low-s, Ed25519 `verify_strict`);
  - HPKE info/AAD bindings.
- **Authentication layer:**
  - canonical CBOR (re-encode check);
  - domain-separated signatures with the type in every digest;
  - signer hash always checked against the verifying key;
  - no key-management message on any runtime link;
  - PROD has no dependency path to MPC code.

## Findings and status

Severity: **H** high · **M** medium · **L** low. Every "fixed" item is in the current code.

| # | Sev | Area | Finding | Status / test |
|---|---|---|---|---|
| S1 | H | engines | Test/attack hooks (`steal_halves`, `adversary_*`, `duplicate_for_test`, `snapshot`/`restore_storage`, `key_from_both_halves`) were compiled into production engines: a "copy a half" API breaks rule 3 | **fixed**: behind feature `sim-hooks`, enabled only by `chp-sim`; `scripts/check-capabilities.sh` fails if a production build has it |
| S2 | H | COLD | Anti-rollback covered only the pools. Freeze state, revocations, rosters, policy versions, the ledger, the replay cache, the address book and UPSTREAM certs could be rolled back by restoring storage | **fixed**: all control state is in COLD's sealed state; a `state` hardware counter advances at boot, on every control change and on every accepted job (ledger / replay cache); a detected restore **fails closed** (every key frozen with `Fault::Rollback`, every pool discarded) · `restoring_cold_control_state_fails_closed`, `rolling_back_the_ledger_is_detected` (both mutation-checked) |
| S3 | M | policy | Fees were invisible to policy: `gas_limit · max_fee` could drain funds past the value limits | **fixed**: fee decoded, `max_fee_per_tx` cap, value + max fee counted in limits · `fees_count_against_limits` |
| S4 | M | SP7 | An `Unfreeze` was not tied to the freeze it lifts: a withheld Unfreeze from incident 1 could lift incident 2 | **fixed**: `Unfreeze` names the freeze's `evidence_hash` · `a_withheld_unfreeze_cannot_lift_a_later_freeze` |
| S5 | M | PROD | PROD kept its halves when an *unlinked* COLD (the likely compromised one) was revoked | **fixed**: any revocation of a non-client key discards PROD's pools · `prod_discards_halves_when_a_disconnected_cold_is_revoked` |
| S6 | M | SP1 | Revoked custodians still counted towards quorum thresholds | **fixed** · `revoked_custodians_do_not_count_towards_a_quorum` |
| S7 | M | SP10 | An address proof was not bound to the question: a valid proof for address Y verified when the requester asked about X | **fixed**: `verify_proof` takes the query; proof echoes `request_id` · `proofs_verify_offline_and_foreign_addresses_alarm` |
| S8 | M | HOT | Presign was not bound to the key/version the operators agreed in the wake window | **fixed**: `PresignOpen` must match the window · `hot_refuses_presign_for_a_key_outside_the_agreed_window` (mutation-checked) |
| S9 | M | COLD | PROD could evict COLD's replay cache with a pushed-forward `prod_time` and have the same request signed twice | **fixed**: cache uses COLD's own clock only; request_id consumed only after all checks · `prod_time_cannot_evict_cold_replay_cache` (mutation-checked: fails on the old code) |
| S10 | M | crypto | `Debug` printed presignature halves, nonces and shares | **fixed**: redacted `Debug` for `EcdsaHalf`, FROST `SecretNonces`, `SecpParty`, `EdParty` · `test_hooks_events_do_not_leak_secrets`, `frost_secrets_are_redacted_in_debug` |
| S11 | M | crypto | Secret copies not zeroized (library `PreSign`, HPKE plaintext, HOT export buffer, FROST nonces, serialized key shares) | **fixed**: `PreSign` zeroized after extraction, HPKE `open` and share serialization return `Zeroizing` buffers, HOT's export plaintext is `Zeroizing`, FROST nonces wiped on drop (the library's `Keyshare` is `ZeroizeOnDrop`) |
| S12 | M/L | SP1 | Certificate expiry not re-checked at use (installed links, UPSTREAM at COLD, clients at PROD, PROD cert at HOT export) | **fixed** · `an_expired_peer_certificate_stops_an_installed_link`, `expired_client_certificates_stop_working` |
| S13 | L | policy | One `PolicyBundle` applied to every key | **fixed**: policy and version per `key_id` |
| S14 | L | COLD | Forged replica bits in a presig id passed "issued" and could push the mark to ~2⁶⁴, bricking the pool | **fixed**: replica bits checked (fault) · `forged_replica_bits_are_a_fault_and_do_not_brick_the_pool` |
| S15 | L | COLD | Undetected restore could reissue presignature ids | **fixed**: blocks come from a dedicated hardware allocation counter |
| S16 | L | COLD | Halves of batches aborted at boot stayed in storage | **fixed** |
| S17 | L | MPC | Bridge dropped DKLs23 abort messages (header-only, filtered as "ask") | **fixed**: `Relay::ask` is a local no-op; every sent message is forwarded |
| S18 | L | MPC | A presign instance's last message could be lost (drain/finish race) | **fixed**: `is_finished` checked before the final drain |
| S19 | L | FROST | Ed25519 small-order / non-canonical points accepted | **fixed**: canonical, torsion-free points only |
| S20 | L | HOT | Stored PROD certificate could be rolled back to an older, still-valid one | **fixed** |
| S21 | L | PROD | Any COLD replica could link; a re-hello didn't abort pending batches; `PresignActivate` digest ignored | **fixed** |
| S22 | L | PROD | Media bundle shape trusted (empty / unsorted ids) | **fixed** |
| S23 | L | caches | Replay caches unbounded by client-chosen `not_after` | **fixed**: TTL capped on the holder's own clock |
| S24 | L | ceremony | Share import / receipts under-checked; 64-bit Y fingerprint; package `info` without manifest hash | **fixed**: kind/key/own-cert checks, full receipt checks, 128-bit fingerprint, `info` binds manifest hash |
| S25 | L | policy | Daily limit bucketed by calendar day (2× across midnight) | **fixed**: rolling 24 h window |
| S26 | L | COLD | A bad job from PROD could burn a genuine request_id; revoking UPSTREAM discarded pools | **fixed** |

## Open items (accepted for the prototype)

| Item | Why open |
|---|---|
| **RUSTSEC-2026-0387** `crypto-bigint` 0.5.5: timing variability in operations meant to be constant-time | Pulled in by `k256` 0.13 / `elliptic-curve` 0.13, which the vendored DKLs23 library is built on. The fix needs the 0.14 line, which means porting the library. |
| DKLs23 peer party id not pinned inside the library (`NoSigningKey`) | Library messages are authenticated by CHP frames, but the library's self-declared party id isn't checked against the frame signer. Low impact (fails or freezes); use library signing keys in production. |
| Path binding lives in COLD's pool selection, not in the half itself | Defence in depth: record the pool or `t·G` in `EcdsaHalf` and check it in `cold_complete`. |
| HOT and PROD state is not rollback-protected | HOT's id high-water mark and PROD's stores live in memory. Reuse is still refused by COLD's own counters (DESIGN §8: "only COLD needs this"). |
| Hardware-counter cost of S2 | Every accepted job now advances COLD's `state` counter once (milliseconds on a TPM/HSM, plus write wear). A deployment that cannot afford this can advance it per block of jobs and accept that a restore loses at most the ledger entries of that block. |
| All ceremony parties in one process | The prototype's ceremony network is in-process (design-notes B9); production ceremonies run each party in its own enclave. |
| ERC-20 / contract-call decoding | `allow_calldata` defaults to false; a policy that allows contract calls needs selector and amount decoding. |
| Unbounded MPC bridge channels; pre-authentication roster checks in `LinkHello` | Resource use only; only COLD dials, and peers are enrolled. |

## Reproduce

```sh
cargo test --workspace                 # includes crates/chp-sim/tests/security_review.rs
./scripts/check-capabilities.sh        # no MPC path in PROD; no sim-hooks in production builds
cargo install cargo-audit && cargo audit
```
