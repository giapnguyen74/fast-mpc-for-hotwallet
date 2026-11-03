# hot-wallet-fast-mpc

Prototype and reference implementation of the **COLD-HOT-PROD protocol (CHP)**: a hot-wallet design
with multiple independent points of failure, built on threshold signatures (DKLs23 for ECDSA, FROST
for Schnorr/EdDSA).

> **Status: prototype, not for production.** This project exists to validate the design and to serve
> as a readable reference. It uses a simulated TEE/HSM, is not audited and must not hold real funds.

## The idea in brief

A hot wallet is normally a single point of failure: steal the secret or reach its API and the funds
are gone. CHP splits it into parties that an attacker must defeat separately:

| Party | Role | Holds |
|---|---|---|
| **COLD** | offline or pull-only signer; re-checks every request on its own | key share, its presignature halves |
| **HOT** | offline, powered off by default; presigns with COLD in agreed wake windows | key share |
| **PROD** | the only internet-facing party; checks requests, sends one fragment per input | HOT's one-time presignature halves only, **no key share** |
| **REC** | offline backup HSM | third key share |

- 2-of-3 threshold key from distributed key generation: the full key never exists.
- HOT → PROD only by removable media; no network link.
- Signing is one message PROD → COLD; COLD verifies the final signature before PROD broadcasts it.
- Two independent policy checks (PROD and COLD), each fed from its own sources.
- Key management happens only in quorum-opened offline ceremonies; no live path can trigger it
  (closing the TSSHOCK / BitForge class of attacks).

The full design, including ten sub-protocols (SP1–SP10), is in [`docs/DESIGN.md`](docs/DESIGN.md).

## How it works: the flows

Each diagram shows what the prototype actually does. To watch these flows live:

- **Web, animated:** `./scripts/web-demo.sh`, then open http://127.0.0.1:14080. The page replays a
  real run recorded from the simulator (`web/trace.json`): every arrow is a real signed frame, and
  node states (HOT power, frozen keys, presignature counts, revoked PROD) come from the engines.
  Play/pause, speed, single-step, and jump to any step.
- **Terminal:** `cargo run -p chp-sim --example demo` prints every message.

### 1. Parties, networks and what each holds

```mermaid
flowchart LR
    subgraph offline["Offline / isolated zone"]
        HOT["HOT<br/>key share s_H<br/>powered off by default"]
        COLD["COLD<br/>key share s_C + its halves<br/>only party that can sign"]
        REC["REC (HSM)<br/>key share s_R<br/>ceremonies only"]
    end
    subgraph online["Internet-facing zone"]
        PROD["PROD<br/>HOT's presignature halves only<br/>NO key share"]
    end
    UP["UPSTREAM<br/>withdrawal service"]
    REQ["Requesters<br/>deposit / audit"]
    CHAIN[("Chain")]
    Q{{"Quorums (M-of-N custodians)<br/>ceremony · policy-PROD · policy-COLD"}}

    COLD -- "dials (link, stream B)<br/>only inside a wake window" --> HOT
    COLD -- "dials (link, streams A/C)" --> PROD
    HOT -. "💾 removable media<br/>sealed bundle, one way" .-> PROD
    UP -- "signed WithdrawalEnvelope" --> PROD
    REQ -- "signed AddressQuery" --> PROD
    PROD -- "broadcast signed tx" --> CHAIN
    Q -. "quorum-signed files<br/>(certs, manifest, policy, unfreeze…)" .-> COLD
    Q -.-> PROD
    Q -. "relayed by COLD as QuorumFile" .-> HOT
```

*Nobody dials COLD or HOT. HOT and PROD have no link. PROD accepts only COLD's link.*

### 2. Lifecycle

```mermaid
flowchart LR
    E["SP1<br/>Enrollment"] --> K["SP2<br/>Key ceremony (DKG)"] --> D["SP3<br/>Share delivery"]
    D --> W["SP4<br/>Wake window + presign"] --> M["SP5<br/>Media → PROD<br/>activation"] --> S["SP6<br/>Signing"]
    S -- "pool low" --> W
    S -- "fault" --> F["SP7<br/>Freeze → quorum Unfreeze"]
    F --> S
    S -- "PROD exits" --> X["Revoke PROD<br/>pools discarded"] --> J["New PROD joins<br/>enroll + link"] --> W
    K --> A["SP10<br/>Address book + proofs"]
```

### 3. SP1 · Enrollment and links: every byte is authenticated before it is parsed

```mermaid
sequenceDiagram
    participant E as Enclave (HOT / COLD / PROD)
    participant Q as Ceremony quorum
    participant C as COLD (dialler)
    participant P as Peer (HOT or PROD)
    E->>E: generate id_key (Ed25519) + wrap_key (X25519)
    E->>Q: attestation(measurement, H(role ‖ replica ‖ id_pk ‖ wrap_pk))
    Q->>Q: vendor sig ✔ measurement on release list ✔ binding ✔
    Q-->>E: QuorumSigned PartyCert
    Note over C,P: later, at runtime
    C->>P: LinkHello{cert, nonce, tls_binding}
    P->>P: cert ✔ role allowed ✔ not revoked ✔ binding = this connection ✔
    P->>C: LinkHello{cert, peer_nonce = COLD's nonce}
    Note over C,P: every frame then passes 6 checks in order:<br/>1 type in registry · 2 signer = peer · 3 seq = last+1<br/>4 role may send type · 5 signature · 6 canonical CBOR
```

### 4. SP2 + SP3 · Making the key and delivering shares

```mermaid
sequenceDiagram
    participant Q as Ceremony quorum
    participant H as HOT
    participant C as COLD
    participant R as REC (HSM)
    participant P as PROD
    Q->>H: CeremonyOpen{Dkg, boot_seq}
    Q->>C: CeremonyOpen{Dkg, boot_seq}
    Q->>R: CeremonyOpen{Dkg, boot_seq}
    Note over H,R: DKLs23 2-of-3 DKG — no dealer, x never exists
    H-->>Q: Y fingerprint
    C-->>Q: Y fingerprint
    R-->>Q: Y fingerprint
    Note over Q: fingerprints equal ✔ test-sign with {H,C} {H,R} {C,R} ✔
    Q->>Q: sign KeyManifest{key_id, Y, public shares}
    Q->>Q: each path's key signs its control statement → sign AddressBook
    Q->>H: SharePackage = HPKE(s_H → HOT.wrap_pk)
    Q->>C: SharePackage = HPKE(s_C → COLD.wrap_pk)
    Note over H,C: open · check s_i·G == Y_i · seal locally
    H-->>Q: ShareReceipt (signed)
    C-->>Q: ShareReceipt (signed)
    Q->>H: Activate
    Q->>C: Activate
    Q->>P: KeyManifest + AddressBook + Activate (public data only)
```

### 5. SP4 · Wake window: HOT wakes only when two operators agree

```mermaid
sequenceDiagram
    participant OC as Operator @ COLD
    participant C as COLD
    participant H as HOT
    participant OH as Operator @ HOT
    OH->>H: power on (LOCKED: accepts only COLD's hello + WakeOpen)
    H-->>OH: display wake counter n
    C->>H: LinkHello
    OC->>C: request window
    C->>H: WakeOpen{PresignSync, max_batches, not_after, wake_seq = n+1}
    Note over H: mode allows stage ✔ key active ✔ caps ✔ wake_seq = n+1 ✔<br/>hardware counter → n+1 BEFORE accepting
    H-->>OH: show digest
    C-->>OC: show digest
    OH->>H: digests match → confirm
    H->>C: WakeAccept{digest}
    OC->>C: confirm → window OPEN
    C->>H: QuorumFile × k (RosterUpdate first, HOT verifies each itself)
    loop each batch (≤ max_batches)
        C->>H: PresignOpen{batch_id, ids above high-water, path}
        H->>C: PresignAccept
        C->>H: PresignMsg (DKLs23 R1–R3)
        H->>C: PresignMsg
        Note over H: seal halves to PROD → MediaBundle 💾 · ERASE
        H->>C: PresignStored{digest}
    end
    C->>H: WakeClose
    Note over H: erase session state · power off
```

### 6. SP5 · Media transfer and three-digest activation

```mermaid
sequenceDiagram
    participant H as HOT
    participant M as 💾 Courier
    participant P as PROD
    participant C as COLD
    H->>M: MediaBundle{HOT cert, signed PresigTransfer(HPKE → PROD)}
    M->>P: carried by a non-custodian
    Note over P: HOT cert ✔ sig ✔ seq 0 ✔ HPKE open ✔<br/>recompute digest ✔ ids above high-water ✔ → Pending
    P->>C: TransferAck{digest}
    Note over C: own digest == HOT's PresignStored == PROD's ack ?
    alt all three equal
        C->>P: PresignActivate → halves ACTIVE on both sides
    else mismatch, deadline passed, or refused import
        C->>P: PresignAbort → halves deleted, batch Aborted for good
    end
```

### 7. SP6 · Signing: one message PROD → COLD

```mermaid
sequenceDiagram
    autonumber
    participant U as UPSTREAM
    participant P as PROD (halves only)
    participant C as COLD (share + halves)
    participant N as Chain
    U->>P: WithdrawalEnvelope (signed: raw_tx, path, policy versions, not_after, time)
    Note over P: ADMISSION (refusal changes nothing):<br/>UPSTREAM sig · fresh · not replayed · key active<br/>own decode · own policy · halves available
    Note over P: take next half → DELETE → ssid → fragment (s₀_h, s₁_h)
    P->>C: Job{envelope verbatim, presig_id, ssid, HPKE(fragment), prod_time}
    Note over C: 1 job_seq seen? → return stored Status (never sign twice)<br/>2 BURN: advance high-water + hardware counter, delete halves
    Note over C: 3 RE-VERIFY ALONE: UPSTREAM sig · times agree · own decode<br/>ssid recomputed · path in book · COLD policy
    Note over C: 4 combine → signature → verify with libsecp256k1
    alt valid
        C->>P: Status{SIGNED, signed_tx}
        P->>N: broadcast
    else policy / ssid / expiry
        C->>P: Status{REJECTED or EXPIRED} (presignature burned)
    else bad fragment / signature fails / reused id
        C->>P: FreezeNotice + Status{FAULT} → key FROZEN everywhere
    end
```

### 8. SP7 · Attack, freeze and recovery

```mermaid
sequenceDiagram
    participant P as PROD (compromised)
    participant C as COLD
    participant H as HOT
    participant Q as Incident quorum
    P->>C: Job: valid UPSTREAM envelope for tx A,<br/>fragment computed for attacker's tx B
    Note over C: COLD decodes tx A itself → signature does not verify
    C->>C: FAULT_FINAL_VERIFY → FREEZE · keep signed Job as evidence
    C->>P: FreezeNotice → PROD freezes, refuses all requests
    Note over P,C: nothing is broadcast · no automatic retry
    Q-->>C: Unfreeze{version n} (M-of-N, verified by COLD itself)
    Q-->>P: Unfreeze{version n}
    C-->>H: QuorumFile(Unfreeze) at HOT's next window
    Note over C,P: a replayed Unfreeze (version ≤ n) is refused
```

### 9. §6.1 · Restarts and storage restore: a presignature is never used twice

```mermaid
flowchart TB
    B["COLD boots"] --> R{"sealed counter value<br/>&lt; hardware counter?"}
    R -- "yes: storage was restored" --> D["discard the pool<br/>floor = highest issued block<br/>OrphanDelete(up to floor) → PROD"]
    R -- "no" --> I["increment pool counter<br/>(closes the open block)"]
    I --> O["delete own halves of closed blocks<br/>OrphanDelete(closed blocks) → PROD"]
    D --> X["any id in a closed block or below the floor<br/>→ REJECTED, never signed"]
    O --> X
```

### 10. Exit and join: replacing PROD needs no key ceremony

```mermaid
sequenceDiagram
    participant Q as Ceremony quorum
    participant C as COLD
    participant P1 as old PROD
    participant P2 as new PROD
    participant H as HOT
    Q->>C: RevocationList{SHA-256(old PROD id_pk)}
    Note over C: drop key · close link · discard EVERY pool<br/>(no refresh: PROD never held a share)
    P1--xC: LinkHello → refused (revoked)
    P2->>Q: attestation → PartyCert (enroll)
    Q->>P2: manifest · book · Activate · policy (public data)
    Q->>C: new PROD's PartyCert (queued for HOT)
    C->>P2: LinkHello → link
    Note over C,H: next wake window
    C->>H: QuorumFile(RevocationList), QuorumFile(new PROD cert)
    Note over H: HOT now seals bundles to the NEW PROD
    H-->>P2: 💾 MediaBundle → activation → signing resumes
```

*A share holder (HOT, COLD or REC) leaving is different: CHP never repairs it. The two survivors
sweep the funds to a pre-registered cold wallet in an offline ceremony, and a new key is made
from scratch (DESIGN SP8 §4).*

### 11. SP10 · Address proofs: no trust in PROD

```mermaid
sequenceDiagram
    participant V as Requester (deposit / audit)
    participant P as PROD
    V->>P: AddressQuery{path or address, nonce} (signed, enrolled)
    alt in the book
        P->>V: AddressProof{entry, AddressBook, KeyManifest, PROD cert} (signed)
        Note over V: offline, pinned roster only:<br/>1 quorum sigs · 2 book version not older<br/>3 re-derive address from Y + path<br/>4 control sig by the derived key · 5 Active · 6 PROD sig + nonce
    else unknown
        P->>V: NotFound (signed) — never "probably ours"
    end
```

## Performance

Measured on **reference hardware**, release build, simulated TEE, in-memory transport (no network).
Full table, method and reading notes: [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

| Operation | Median | p95 | DESIGN target |
|---|---:|---:|---|
| Withdrawal round trip, every check, no network | 0.79 ms | 1.53 ms | < 100 ms p99 incl. one hop |
| Presign, per presignature (batch of 64) | 3.5 ms | 3.6 ms | — |
| Whole key ceremony (enroll + DKG + test signatures + book + delivery) | 0.47 s | 0.53 s | — |

The online path costs well under a millisecond of compute per withdrawal; a deployment adds one
network hop PROD → COLD. Presign (offline, inside wake windows) is the expensive part.

## Documents

- [`docs/DESIGN.md`](docs/DESIGN.md) — the protocol design.
- [`docs/PLAN.md`](docs/PLAN.md) — implementation plan: scope, workspace layout, phases, testing.
- [`docs/design-notes.md`](docs/design-notes.md) — findings and proposed design changes from building it.
- [`docs/SECURITY.md`](docs/SECURITY.md) — security review: findings, fixes, regression tests, open items.
- [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) — timings on reference hardware.
- [`crates/chp-frost/REVIEW.md`](crates/chp-frost/REVIEW.md) — FROST / Taproot validation report.

## Layout

Rust workspace (see [`docs/PLAN.md`](docs/PLAN.md)):

| Crate | Purpose |
|---|---|
| `chp-wire` | closed message registry, deterministic CBOR, signed frames |
| `chp-auth` | SP1: certificates, authorization matrix, 6-step frame check, quorum, revocation |
| `chp-crypto` | hashing, `t_path`, HPKE, identity keys, ECDSA fragment/completion, independent verifier (no MPC code) |
| `chp-mpc` | adapter over the vendored DKLs23 library: DKG, presign, refresh (never linked by PROD) |
| `chp-frost` | FROST δ-masked split signing, Taproot sign factors, BIP340/86/341 vectors |
| `chp-tee` | simulated TEE/HSM: keys, attestation, hardware monotonic counters |
| `chp-core` | shared engine pieces: digests, keyring, address book and proof verifier |
| `chp-chain`, `chp-policy` | EIP-1559 decoder; reference policy with per-party ledger |
| `chp-engine-hot`, `chp-engine-cold`, `chp-engine-prod` | one engine per role |
| `chp-ceremony` | enrollment, DKG ceremony, share packages, address book, REC |
| `chp-sim` | in-process simulator and end-to-end / adversarial tests |
| `thirdparty/dkls23` | vendored Silence Laboratories DKLs23 (third-party, own non-commercial license, see `THIRD_PARTY_LICENSES.md`) |

## Running

```sh
./scripts/web-demo.sh                 # animated web demo of a real run → http://127.0.0.1:14080
cargo run -p chp-sim --example demo   # narrated run of every flow above, every message printed
cargo run --release -p chp-sim --example bench   # timings (see docs/BENCHMARKS.md)
cargo test --workspace                # 111 tests: crypto validation, SP1, engines, end-to-end, adversarial, security regressions
./scripts/check-capabilities.sh       # PROD has no MPC code path; no simulation hooks in production builds
```

## Status

Phases 0–6 of the plan are implemented: SP1–SP7 and SP10 for ECDSA/EVM run end to end in the
simulator, including compromised-PROD, storage-restore and media-failure scenarios. FROST
cryptography is validated but not yet wired into the engines; SP8 ceremonies and SP9 QR are not
built yet. Findings about the design: [`docs/design-notes.md`](docs/design-notes.md).

## Licensing

The code of this repository is MIT-licensed ([`LICENSE`](LICENSE)). Third-party components keep
their own licenses: `thirdparty/dkls23` is under the Silence Laboratories **Non-Commercial**
License. Commercial use of it is the user's own responsibility. See
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) and [`NOTICE`](NOTICE).

## Security

An internal security review (three independent reviewers plus `cargo audit`) found 2 high, 10
medium and 14 low issues. All 26 are fixed, each with a regression test where practical; a few
items are accepted as open for the prototype. A compromised PROD could not get an unauthorised
signature, reuse a presignature or extract COLD's secrets. See [`docs/SECURITY.md`](docs/SECURITY.md).

## Warnings

Several constructions in the design are marked **REVIEW REQUIRED** (FROST δ masking, Taproot sign
factors, CHP path derivation). They are implemented here for evaluation only and need independent
cryptographic review before any use.
