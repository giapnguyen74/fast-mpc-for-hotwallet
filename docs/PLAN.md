# Implementation plan: COLD-HOT-PROD protocol (CHP)

Source design: [`docs/DESIGN.md`](DESIGN.md) (referred to below as DESIGN).
Language: **Rust**. TEE/HSM: **software simulator**.
DKLs23: **vendored library in `thirdparty/dkls23/`** (not yet present in the repo).

## 0. Scope

This is a **prototype and reference implementation** of the design, **not a production system**.

**Goals**
- Show that the design works end to end, and expose any gaps or contradictions in DESIGN.
- Be a readable reference: each rule and check maps to a DESIGN section, cited in code (`// DESIGN SP6 §3 step 4`).
- Produce test vectors and a normative wire-format description that another implementation could check itself against.
- Serve as a test bed for the crypto items marked REVIEW REQUIRED (FROST δ masking, Taproot math, `t_path`).

**Non-goals**
- Production hardening, high availability (HA), performance tuning at scale, or operational tooling.
- Real TEE/HSM backends. The `chp-tee` traits leave room for them, but only the simulator is built.
- Real-funds deployment. Devnets, regtest and testnets only.
- Security certification. The code is not audited, and DESIGN §6.3 says any production implementation needs an independent audit.

**Consequences for how it is built**
- Clarity over cleverness: straightforward code, few dependencies, no premature optimisation.
  The latency targets in DESIGN SP6 §7 are measured and reported, not tuned for.
- Security checks are still implemented **fully and in the specified order**. A reference that
  skips checks would be useless as a reference.
- Where DESIGN is ambiguous, the prototype picks one reading and records it in
  `docs/design-notes.md` as feedback on the design.

---

## Status (2026-11-03)

| Phase | State | Where |
|---|---|---|
| 0 Crypto spikes | **done**: DKLs23 split + `t_path` + refresh validated; FROST δ masking + Taproot validated against BIP340/BIP86/BIP341 vectors | `chp-mpc/tests`, `chp-frost` (+ `REVIEW.md`) |
| 1 Wire, SP1, TEE sim, harness | **done** | `chp-wire`, `chp-auth`, `chp-tee`, `chp-sim` |
| 2 SP2 + SP3 | **done** (ceremony network simplified, design-notes B9) | `chp-ceremony`, HOT/COLD `import_share` |
| 3 SP4 + SP5 | **done** | `chp-engine-hot`, `chp-engine-cold`, `chp-engine-prod` |
| 4 SP6 (ECDSA / EVM) | **done** | engines + `chp-chain`, `chp-policy` |
| 5 SP7 | **done** (freeze/unfreeze, revocation, policy, retire, PoolStatus, OrphanDelete, restore detection) | engines |
| 6 SP10 | **done** (EVM addresses, proofs, offline verifier) | `chp-core::address`, PROD |
| 7 FROST engines + BTC | crypto done; engines not wired | `chp-frost` |
| 8 SP8 | library refresh validated; ceremony flow not wired | `chp-mpc/tests` |
| 9 SP9 QR | not started | |
| 10 Demo / vectors | not started | |

Test count: 111 (`cargo test --workspace`). Security review: [`SECURITY.md`](SECURITY.md). Capability check: `scripts/check-capabilities.sh`.
Design feedback collected while building: [`design-notes.md`](design-notes.md).

Layout differences from §2: `chp-mpc` (MPC library adapter, split out of `chp-crypto` so PROD
has no path to it) and `chp-frost` were added; `chp-store` lives inside the engines,
`chp-address` inside `chp-core`; `chp-transport` is not built yet (the simulator moves bytes).

---

## 1. Principles

1. **Sans-I/O engines.** Every party (COLD, HOT, PROD, ceremony) is a pure state machine:
   `handle(input) -> Vec<Output>` where inputs are verified frames, operator actions or timer ticks,
   and outputs are frames to send plus storage effects. No sockets, files or clocks inside an engine.
   All parties run together in one deterministic in-process simulator long before any network exists.
2. **Capability by construction (DESIGN §3, layer 2; rule 6).** One crate per role. `chp-prod` does not
   depend on presign, DKG, refresh or `SharePackage` code at all, so "no code path" is enforced by the
   compiler, not by configuration. A CI check (`cargo tree`) asserts the forbidden dependencies stay out.
3. **Hardware behind traits.** Sealing, monotonic counters, attestation, identity keys, randomness and
   time are traits with `sim` implementations only (real backends are a non-goal, see §0).
4. **Authenticated before parsed (rule 1).** One shared frame checker (DESIGN SP1 §5, six steps, in order)
   is the only way bytes reach an engine.
5. **Forward-only, take = delete (rules 2, 3).** Durable delete happens before compute; states are enums
   with only forward transitions; terminal states are final.
6. **The protocol never deletes a share (rule 8).** No API in any engine can delete a share. Enforced by
   type design (shares are not removable from the store) and by a test.
7. **De-risk crypto first.** The items marked REVIEW REQUIRED in DESIGN are spiked in phase 0 before
   anything is built on them.

---

## 2. Workspace layout

```
Cargo.toml                  workspace
thirdparty/dkls23/          vendored DKLs23 library (pinned, patched only via documented diffs)
crates/
  chp-wire/                 closed message registry, deterministic CBOR (re-encode check),
                            SignedMsg, QuorumSignedMsg, domain tags, size caps
  chp-auth/                 SP1: PartyCert, roster + RosterUpdate, RevocationList, may_send table,
                            6-step frame checker, LinkHello, QuorumSignedMsg verification, anti-rollback
  chp-crypto/               adapters over thirdparty/dkls23 and frost-core; t_path derivation;
                            Taproot sign factors; HPKE wrappers; independent verifiers
                            (libsecp256k1 for ECDSA/BIP340, ed25519-dalek strict for Ed25519)
  chp-tee/                  traits: Sealer, MonotonicCounter, Attestor, IdentityKey, Rng, Clock
    sim/                    software simulator: in-memory/file-backed, restorable snapshots for tests
  chp-store/                forward-only state machines: key state, batch state, pools,
                            per-pool high-water + block counters, replay caches, outbox
  chp-policy/               policy trait + bundle versioning; reference policies (limits, allowlist)
  chp-chain/                tx decoders + message/sighash extraction: evm (phase 4), btc (phase 7),
                            ed25519 chain (phase 7)
  chp-engine-cold/
  chp-engine-hot/
  chp-engine-prod/
  chp-ceremony/             SP2 DKG, SP3 export/import, SP8 refresh, SP10 address-sign, quorum tool
  chp-address/              SP10 address derivation + standalone proof verifier (for requesters)
  chp-transport/            link (mTLS/QUIC), media bundle files, QR fountain codec (SP9)
  chp-sim/                  in-process harness: all parties, operators, adversaries, fault injection
bins/
  chp-cold, chp-hot, chp-prod, chp-quorum, chp-ceremony   thin I/O shells around the engines
docs/
  PLAN.md, wire-format.md (written in phase 1), review/ (crypto review notes per item)
```

Key external crates (to confirm in phase 0): `frost-core`, `frost-ed25519`, `frost-secp256k1-tr`,
`k256`, `secp256k1` (independent verifier), `ed25519-dalek`, `hpke`, `ciborium` or `minicbor`
(with our own canonical check), `sha2`, `proptest`, `cargo-fuzz`.

---

## 3. Phases

Each phase ends with its exit criterion green in CI. Later phases do not start while an earlier
exit criterion is red.

### Phase 0 — Crypto spikes and library audit (gate for everything)

| Spike | Question | Exit |
|---|---|---|
| 0.1 DKLs23 API | Does `thirdparty/dkls23` expose, per party: DKG with base-OT seeds stored in the share; 2-party presign R1–R3 with consistency checks in R3; the presign output `(sid, R, φ_i, s₀′_i, s₁_i)` as serialisable data; a way to compute the fragment with `m + r·t` instead of `m`? | API map written to `docs/review/dkls23-api.md`; list of needed patches (if any) as minimal diffs |
| 0.2 Key-equivalence check | Reproduce DESIGN §6 `x = Σs₀′ / (r·Σφ)` in a test | test documents the risk and is kept as a regression |
| 0.3 Path tweak | `t_path = H("chp-derive-v1" ‖ key_id ‖ Y ‖ path) mod q`; ECDSA verify against `P = Y + t·G` | signatures verify with libsecp256k1 |
| 0.4 FROST δ masking ⚠ | Implement split on `frost-core` (`s′_h = s_h + δ`, `s′_c = s_c + (i_c/i_h)·δ`), COLD's check against `Y′_h` | correct signatures; negative tests (wrong δ, wrong fragment) caught |
| 0.5 Taproot sign factors ⚠ | `g_P`, `g_Q`, `g`, `g_R`, `t_eff` | passes BIP340/BIP341 vectors incl. odd-y derived keys and nonces |
| 0.6 Canonical CBOR | choose crate; implement re-encode check | rejects unknown fields, trailing bytes, non-minimal ints |

Outputs of 0.4 and 0.5 go into `docs/review/` for the independent cryptographic review the design
requires. FROST work in phase 7 is blocked until that review accepts them (fallback: HOT signs live).

### Phase 1 — Foundations: wire, SP1, TEE simulator, harness

- `chp-wire`: registry of every message type in DESIGN SP1 §6; `SignedMsg` sig =
  `Ed25519(id_key, "chp-v1" ‖ type ‖ seq ‖ SHA-256(body))`; `QuorumSignedMsg` (M distinct roster members).
- `chp-auth`: certificates, roster, revocation, `may_send`, 6-step checker, `LinkHello` with TLS-exporter
  binding (simulated exporter in the harness), monotonic versions for control objects.
- `chp-tee::sim`: identity/wrap keys, sealing, monotonic counters (with a "restore snapshot" fault hook),
  simulated attestation (measurement + user_data), controllable clock.
- `chp-sim`: message bus with drop/delay/reorder/duplicate injection.
- Write `docs/wire-format.md` (normative field lists) — required for a second implementation (Q5).
- **Decide before freezing the wire format:** where signed time lives (DESIGN §9.3 asks for two
  independent signed time sources but no message carries them). Proposal: `upstream_time` in
  `WithdrawalEnvelope`, `prod_time` in `Job`, accepted only if within a bound of each other and ≥ local floor.

Exit: exhaustive test of the role matrix (every type × every role); replay, reorder, wrong signer,
wrong role, non-canonical body, revoked cert, roster rollover all refused before parsing.

### Phase 2 — SP2 DKG + SP3 share delivery (DKLs23, secp256k1)

- Ceremony runner on the simulated isolated network: `CeremonyOpen`, cross-attestation, signed rounds,
  `Y` fingerprints, pairwise test signatures, `KeyManifest`.
- SP3: HPKE seal to `wrap_pk` with the specified `info`; import checks in order; `s_i·G == Y_i`;
  `ShareReceipt`; quorum `Activate`; key `ACTIVE_PENDING → ACTIVE`.
- PROD accepts manifest/`Activate` only and refuses any `SharePackage` (test).
- HOT/COLD boot counters and `boot_seq` checks.

Exit: three parties + quorum produce an active key in the simulator; every SP3 §5 failure row tested.

### Phase 3 — SP4 presign + SP5 media transfer

- Wake window: `WakeOpen` / `WakeAccept` / `WakeClose`, digest confirm by two simulated operators,
  hardware wake counter, return stages (`PresignSync`, `Dkg`, `ControlOnly`), `QuorumFile` relay.
- Pools `(key_id, key_version, path)`, id layout `hot_replica ‖ cold_replica ‖ block ‖ index`,
  per-pool counters, batch ≤ 256, `PresignOpen` checks, R1–R3, batch digest.
- SP5: `PresigTransfer`, `MediaBundle`, HOT erase + `PresignStored`, PROD import checks,
  `TransferAck`, 3-digest activation, `PresignActivate`, all abort paths, `import_deadline`.

Exit: batches reach `Active` on both sides; every SP4 §6 and SP5 §5 row tested; R3 fault freezes with
no retry; replayed/late bundles refused.

### Phase 4 — SP6 online signing (ECDSA, EVM) — first end-to-end milestone

- `chp-chain::evm`: decode legacy/EIP-1559 txs, chain-id check, sighash; refuse raw hashes/personal_sign.
- `chp-policy`: reference limit + allowlist policy; separate bundle sequences for PROD and COLD.
- PROD: admission (no state change), take = delete in increasing id order, ssid, fragment, HPKE to COLD, `Job`.
- COLD: `job_seq` idempotency, advance high-water + burn, independent re-verification, own decode,
  own policy, combine, low-s normalisation, recovery id, independent verify against `Y_p`, `Status`.
- Fault paths: `FAULT_PROD_FRAGMENT`, `FAULT_FINAL_VERIFY`, `FAULT_PRESIG_STATE` → freeze.

Exit: signed EVM tx on a local devnet (anvil) end to end through the simulator; every SP6 §6 outcome
tested; property test: no presignature id ever contributes to two signatures, including across
simulated COLD restarts and storage restores.

### Phase 5 — SP7 control

- `FreezeNotice`, quorum `Unfreeze` (version monotonic), `RevocationList` (pool discard rules),
  `PolicyBundle` with `target`, `PoolStatus` reconciliation, `OrphanDelete` at COLD boot,
  restore detection (sealed counter value < hardware value → discard pool, set floor).
- Optional quorum separation (per-function rosters, `RosterUpdate`).

Exit: every row of DESIGN SP7 §3 "what freezes" table tested; captured `Unfreeze` cannot be replayed.

### Phase 6 — SP10 address book & proof

- Address derivation (EVM first), `AddressBook`, control signature in the ceremony,
  `AddressSign` ceremony with any two share holders, `AddressQuery` / `AddressProof` / `NotFound`.
- `chp-address` verifier as a standalone library with no dependency on engines.
- Book gates presign (HOT) and signing (COLD).

Exit: forged/foreign address, stale book, retired address all raise alarms in the verifier.

### Phase 7 — FROST: Ed25519, then Taproot; Bitcoin decoder

Blocked on phase 0.4/0.5 review. Ed25519 (root path only) first, then Taproot with BIP86 tweak,
`ShareMasks`, δ lifecycle (deleted on use/discard), `chp-chain::btc` (SegWit/Taproot only,
`SIGHASH_ALL`/`DEFAULT` only, amounts committed).

Exit: test vectors + end-to-end on regtest and an Ed25519 devnet; δ never leaves COLD's sealed store.

### Phase 8 — SP8 refresh & PROD replacement

- DKLs23 refresh, FROST zero-sharing refresh; `KeyManifest v+1`, receipts, `Activate(v+1)`,
  "every new pair signs, old+new fails" test, `Retire(v)`, pools discarded, shares kept.
- PROD replacement: revoke, enroll, deliver new `PartyCert` to HOT via `QuorumFile`.

Exit: refresh in simulator; old version unusable in every engine; no share deleted anywhere.

### Phase 9 — SP9 QR transport

- `QrFrame` binding, persistent per-direction `dir_seq`, `QrPairing`, fountain-coded animated QR,
  size/part caps before decode, gap rule, byte-identical duplicate replay of stored reply.
- Simulated camera/display channel in the harness; real codec behind a feature flag.

Exit: SP9 §7 failure rows tested; decoder fuzzed.

### Phase 10 — Multi-process demo and reference artefacts

- Run each party as its own process over local mTLS links with exporter binding, and media bundles as
  files on disk, so the demo shows real separation. The TEE stays simulated.
- A scripted demo of the full lifecycle: DKG → presign → media → signing → freeze → unfreeze → refresh.
- Hash-chained, signed audit log (DESIGN §10.2), kept simple.
- Publish test vectors (frames, digests, ssids, fragments, address proofs) in `docs/vectors/`.
- `docs/design-notes.md`: ambiguities, gaps and proposed DESIGN changes found while building.
- Out of scope (production): real TEE/HSM backends, hardware counters, sandboxed parser process,
  HA replicas, audit preparation. The traits and notes say where they would plug in.

---

## 4. Testing strategy

- **Rule tests:** one test per numbered rule in DESIGN §4 "Rules every sub-protocol obeys".
- **Table tests:** every row of every failure/outcome table in SP3–SP9 and §7 (side effects).
- **Adversary roles in `chp-sim`:** malicious PROD (bad fragment, replayed job, swapped envelope,
  rolled-back store), malicious network, restored COLD storage, replayed quorum files.
- **Property tests (`proptest`):** single use of presignatures; forward-only states; no share deletion.
- **Fuzzing (`cargo-fuzz`, light):** short fuzz runs on the frame checker, CBOR and QR reassembly,
  enough to show that the parsers refuse malformed input. Long fuzzing campaigns are a production concern.
- **Dependency checks:** CI asserts `chp-engine-prod` has no path to presign/DKG/refresh code.

## 5. Open decisions (to settle as phases arrive)

| When | Decision |
|---|---|
| Phase 0 | Whether `thirdparty/dkls23` needs patches, and how they are tracked |
| Phase 1 | Signed-time fields (see phase 1) |
| Phase 7 | Outcome of the FROST δ / Taproot review; fallback is live HOT signing for Schnorr |
| Production (not this project) | TEE/HSM platform per party; seal-to-measurement vs seal-to-release-identity (DESIGN §9.4) |
| Later | Independent second implementation of COLD's decoder + policy (DESIGN Q5) |

## 6. Immediate next steps

1. Vendor the DKLs23 library into `thirdparty/dkls23/`.
2. Create the Cargo workspace skeleton (empty crates, CI with fmt/clippy/test).
3. Phase 0.1: map the DKLs23 API against DESIGN SP4/SP6 requirements.
