# Benchmarks

Measured on **reference hardware** (a single developer-class machine), release build,
2026-11-03. Numbers are medians and 95th percentiles over `n` runs. They are indicative only:
this is a prototype with a **simulated TEE**, and the simulator moves bytes in memory, so no
network latency is included.

Reproduce:

```sh
cargo run --release -p chp-sim --example bench -- --md docs/BENCHMARKS-run.md
```

## Groups

- **A. Online signing path**: the per-input cryptography on the latency-critical path, single
  thread. Compare with the estimates in DESIGN SP6 §7 (the "Note" column).
- **B. SP1 authentication**: cost of signing and checking one frame (Ed25519, deterministic CBOR).
- **C. MPC**: multi-party protocols run in-process (all parties on one machine, tokio tasks).
- **D. Protocol end to end**: real engines through the simulator with every check: framing, frame
  checks, HPKE, decoding, policy, ledger, digests, independent verification.

## Results

| Group | Operation | Median | p95 | n | Note |
|---|---|---:|---:|---:|---|
| A | DKLs23 · PROD fragment (s₀_h, s₁_h) | 17.4 µs | 29.6 µs | 300 | DESIGN SP6 §7 estimate ~15 µs |
| A | DKLs23 · COLD combine + low-s + libsecp256k1 verify | 124.7 µs | 237.9 µs | 300 | estimate ~160 µs |
| A | FROST-Taproot · PROD fragment z_h (incl. session) | 179.2 µs | 414.1 µs | 300 | estimate ~140 µs |
| A | FROST-Taproot · COLD check + combine + BIP340 verify | 541.5 µs | 922.9 µs | 300 | estimate ~400 µs |
| A | FROST-Ed25519 · PROD fragment z_h (incl. session) | 71.6 µs | 262.2 µs | 300 | estimate ~70 µs |
| A | FROST-Ed25519 · COLD check + combine + strict verify | 206.9 µs | 540.7 µs | 300 | estimate ~240 µs |
| A | HPKE seal, 96-byte fragment (X25519/ChaCha20-Poly1305) | 127.0 µs | 187.6 µs | 300 | PROD → COLD |
| A | HPKE open, 96-byte fragment | 103.2 µs | 157.6 µs | 300 | at COLD |
| B | sign a frame (Ed25519 + deterministic CBOR) | 25.9 µs | 35.0 µs | 300 |  |
| B | check a frame (decode, signature, canonical body) | 80.7 µs | 98.9 µs | 300 | steps 1–6 cost |
| C | DKLs23 DKG 2-of-3 (3 parties, in-process) | 407.95 ms | 484.44 ms | 10 | MPC rounds only |
| C | DKLs23 presign, one presignature (2 parties) | 17.33 ms | 22.22 ms | 300 | R1–R3 incl. OT multiplication |
| C | DKLs23 key refresh (3 parties) | 427.34 ms | 453.09 ms | 5 | SP8 primitive |
| D | SP1–SP3: enroll + DKG ceremony + test sigs + 2-address book + share delivery + activate | 474.06 ms | 528.18 ms | 3 | whole ceremony |
| D | SP4 presign window, per presignature (batch of 64, framed + checked) | 3.54 ms | 3.55 ms | 3 | amortised |
| D | SP5 PROD import of one bundle (64 halves: verify, HPKE, digest) | 703.5 µs | 1.37 ms | 3 |  |
| D | SP6 PROD: admission + take half + fragment + seal + sign Job | 213.4 µs | 547.7 µs | 150 | decode, policy, ssid |
| D | SP6 COLD: frame check → burn → re-verify → combine → verify → Status → PROD broadcast | 504.1 µs | 1.11 ms | 150 | in-memory transport |
| D | SP6 withdrawal round trip, one input (no network) | 793.2 µs | 1.53 ms | 150 | design target p99 < 100 ms incl. one hop |
| D | SP10 PROD answers AddressQuery (signed proof) | 45.8 µs | 177.9 µs | 100 |  |
| D | SP10 requester verifies proof offline (quorum sigs, derivation, control sig) | 415.5 µs | 1.17 ms | 100 |  |

## Reading the numbers

- **The online path is cheap.** One input costs PROD about 17 µs (DKLs23 fragment) and COLD about
  125 µs (combine + independent verification); these are in line with DESIGN SP6 §7. FROST is
  costlier because every fragment needs a session (binding factors, group commitment) on both
  sides, plus COLD's fragment check.
- **A full withdrawal is under 1 ms of compute** (median 0.8 ms) through every protocol check:
  UPSTREAM signature, two independent decodes and policies, ssid, burn, HPKE, combination,
  libsecp256k1 verification and transaction assembly. A deployment adds one network hop PROD →
  COLD (linked route) and PROD's broadcast, which the 100 ms p99 target in DESIGN SP6 §7 budgets for.
- **Presign dominates offline cost.** A single DKLs23 presignature takes ~17 ms (OT-based
  multiplication). A batch runs its instances concurrently: ~3.5 ms per presignature amortised in
  a batch of 64, so a 256-id batch takes about a second inside a wake window.
- **Ceremonies are sub-second compute.** DKG or refresh take ~0.4 s of MPC; the whole SP1–SP3
  ceremony with test signatures and address control signatures is ~0.5 s. Real ceremonies are
  bounded by people (custodians, read-aloud fingerprints, media), not compute.
- **p95 spread** comes from tokio scheduling and other load on the machine; treat medians as the
  comparison point.

## Not measured

Real TEE / HSM overhead (attestation, sealing, hardware monotonic counters, which take milliseconds
per increment; DESIGN §6.1 increments once per block, not per presignature), network and QR
transport, and disk persistence.
