# Security review

Internal review of the prototype, 2026-11-03 (two rounds). Three independent reviewers covered:

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


## Round 2 (re-review of the fixes + fresh attacker scenarios)

Two more reviewers: one audited every round-1 fix for bypasses and regressions; one worked through
attacker scenarios round 1 did not cover (compromised HOT, compromised UPSTREAM, malicious COLD
host outside the enclave, network attacker, colluding pairs). No scenario produced a signature
without a valid UPSTREAM envelope or extracted COLD's share. Findings, all fixed with regression
tests in `crates/chp-sim/tests/security_review_r2.rs` (and SP1 tests); tests marked † were
mutation-checked (fail on the unfixed code):

| # | Sev | Finding | Fix · test |
|---|---|---|---|
| R1 | H | **S2 bypass**: restoring a snapshot taken while the key was already frozen kept the *old* freeze evidence, so an old public Unfreeze lifted it and the rolled-back state (e.g. a revoked UPSTREAM) came back | rollback **overwrites** every key's freeze; evidence bound to the boot's counter value; restore announced (event + FreezeNotice to PROD) · `r1_…` † |
| R2 | H | **COLD daily limit bypass by a malicious COLD host** feeding a clock walked through the past | policy and ledger use the authenticated job time; COLD's time floor moves only on signed request times (never past COLD's own clock, never back) · `r5_…` † (with an honest-clock control) |
| R3 | M | S23's TTL cap reopened double-signing for **future-dated envelopes** | COLD **rejects signed times in the future** (UPSTREAM's or PROD's signed time more than `max_time_skew` ahead of COLD's clock; tunable for drifting air-gapped clocks). Independently, the cap is removed: entries live until `not_after + skew` and are pruned **only by COLD's authenticated floor**, while expiry is checked at or above that floor, so replay safety does not depend on clocks at all · `r2_…` †, `r2b_…` (drift within tolerance signs; 10 min slow from the start is refused), `r2c_…` † (host clock jump cannot prune) |
| R4 | M | **PROD's daily limit ignored in-flight jobs** (burst of requests) | amount reserved at admission, released if not signed · `r6_…` |
| R5 | M | **Deep RLP nesting** overflowed the stack (process abort) | depth limit 8 · `chp-chain` unit test (20 000 levels) |
| R6 | M | **Link frames not bound to the session**: frames replayed into a later link (old FreezeNotice re-froze; old PoolStatus deleted a batch) | every link frame signs a session id `H(dialer nonce ‖ responder nonce ‖ TLS binding)` · `frames_from_an_earlier_session_cannot_be_replayed` |
| R7 | M | **High-security mode bypass**: a `Dkg` window could refill the old key; operators approved digests blind | a `Dkg` window must name a new key; both sides display stage, key, version, caps, deadline · `r7_…` |
| R8 | M | **Compromised HOT could abort Active batches** (and send PresignStored out of order) | PresignRefuse only while Opened/Rounds; PresignStored once, in Rounds · `r8_…` |
| R9 | M | Crash between counter increment and sealing looked like a restore (fail-closed outage on demand) | seal `hw+1` first, then increment; boot accepts and catches up · `r3_…` |
| R10 | M | `sim-hooks` gate unreliable (script blind to a crate's own features, failed open; workspace builds unified the feature) | hooks enabled only through `chp-sim` **dev-dependencies** (never unified into normal builds); script checks resolved features per engine and for the workspace, fails closed · mutation-checked (`default = ["sim-hooks"]` is caught) |
| R11 | L/M | Revoking a requester or custodian discarded every pool | `RevocationList` entries carry the role; only HOT/COLD/PROD revocations discard · `r4_…` |
| R12 | L | One Unfreeze could not lift freezes held with different evidence; an Unfreeze for an unfrozen key burned a version | Unfreeze names a set of evidence; refused (nothing consumed) when not frozen |
| R13 | L | A far-future host clock made COLD unusable for good (sealed floor) | the floor moves only on authenticated time · `r9_…` |
| R14 | L | A pending (not yet activated) manifest stopped signing with the current version | `current()` = highest **Active** version · `r10_…` |
| R15 | L | A forged HOT bundle could raise PROD's high-water mark and block the pool | the mark moves only on `PresignActivate`; HOT replica bits and duplicate ids checked |
| R16 | L | One address book per party shared by all keys | one book per key |
| R17 | L | Address-proof "wrong entry" alarm raised before PROD's signature was checked; case-insensitive comparison for all chains | binding checked after authentication; exact match except EVM hex |
| R18 | L | HOT re-hello mid-window; any COLD replica could link to HOT | one hello per boot, before any window; COLD replica pinned |
| R19 | L | Control messages lost while unlinked; queued HOT files / OrphanDeletes lost on COLD reboot | sealed outgoing queues at COLD, queue at PROD, flushed on link |
| R20 | L | PROD `job_seq` restarted after a PROD restart | starts from a hardware boot counter |
| R21 | L | PoolStatus crossing a PresignActivate could delete a new batch | reconciliation limited to batches both sides hold as Active |
| R22 | L | `PartyCert.key_ids` never enforced; UPSTREAM could sign for any key | enforced at PROD and COLD when non-empty |
| R23 | L | Smaller: HOT dropped exports silently (now PresignRefuse), COLD import version check, Activate-after-Retire consumed a version, shares imported without a state-counter advance | fixed |

Documented, not changed: **HOT-made bad halves are blamed on PROD** (the batch digest covers only
public parts; a compromised HOT can corrupt the halves it seals for PROD, and the first job then
fails as a PROD fragment fault). Incident response must treat a `FAULT_PROD_FRAGMENT` on a fresh
batch as possibly HOT. The library's `PreSign` is `Copy`, so its zeroization is best-effort.

### Follow-up: a freeze ends every presignature

A freeze now discards every presignature of the key on COLD and PROD, and the Unfreeze repeats
this as a backstop, so signing resumes only with new batches from a fresh wake window. Halves a
compromised PROD copied during the incident are then useless, even if COLD is breached later.
Key shares are untouched (design-notes E8). Test: `compromised_prod_cannot_redirect_funds`
(the stolen half is refused after the Unfreeze; mutation-checked).

## Round 3 (deep review)

Four reviewers with different methods: an audit of the vendored DKLs23 library internals with a
malicious-peer harness, randomised attack-sequence testing of the protocol invariants, fuzzing of
every untrusted-input parser, and a design-level threat analysis. Tests in
`crates/chp-sim/tests/security_review_r3.rs` († = mutation-checked).

| # | Sev | Finding | Fix · test |
|---|---|---|---|
| D1 | **Critical** | **Selective-failure OT probe in DKLs23 presign.** A malicious presign peer crafts its OT messages so that each instance's pass/abort reveals 4 bits of the honest side's long-term base-OT secret (Δ); about 500 probes recover Δ, then one more presign recovers that side's signing share, so a compromised HOT gets the key with COLD's half (confirmed with the reviewer's harness, re-run independently). CHP's "freeze on presign fault, no retry" was weaker than designed: one batch gave up to 256 probes before its single freeze; link loss, window close and deadline aborts gave probes **with no freeze at all**; and after an Unfreeze the same Δ kept presigning | freeze on the **first** failed instance (the rest of the batch stops at once); every abort path checks for failed instances first; a presign fault **taints the key version for good** (no presign even after Unfreeze; recovery is a refresh with fresh OT seeds, or a sweep to a new key); a peer's Presign FreezeNotice taints too; batch size capped at 16 as a security parameter · `a_failed_presign_instance_freezes_and_taints_the_key_version` †, `a_link_loss_after_a_failed_instance_still_freezes` †, `batch_size_is_capped` |
| D2 | **Critical** (design) | **The ceremony quorum could swap a key.** A quorum-signed "refresh" manifest v+1 with another group key was accepted, and a different manifest for an installed version was silently ignored | a new version must keep the key's group key, protocol and chain; a different manifest for an installed version is refused · `a_new_key_version_cannot_swap_the_group_key` |

The remaining design-level findings of round 3 need decisions and are listed in
[`design-notes.md`](design-notes.md) section F.

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
