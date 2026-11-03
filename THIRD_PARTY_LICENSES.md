# Third-party licenses

The code of this repository is licensed under the MIT License (see [`LICENSE`](LICENSE)),
**except** the third-party components listed below, which keep their own licenses.

| Component | Location | License | Notes |
|---|---|---|---|
| Silence Laboratories DKLs23 (`sl-dkls23` 1.0.1-beta) | [`thirdparty/dkls23/`](thirdparty/dkls23/) | [Silence Laboratories Non-Commercial Use License Agreement](thirdparty/dkls23/LICENSE) | modified, see [`NOTICE`](NOTICE) and [`docs/thirdparty-patches.md`](docs/thirdparty-patches.md) |

Crates fetched from crates.io at build time (k256, secp256k1, frost-*, hpke, ed25519-dalek, …)
are under their own licenses, listed in each crate's metadata (`cargo metadata`).

## Commercial use

The DKLs23 library permits **non-commercial use only**. Anyone who uses this repository, or a
program built from it, commercially is responsible for obtaining a Commercial Use License from
Silence Laboratories (info@silencelaboratories.com) or replacing the library. This repository
grants no rights to `thirdparty/dkls23` beyond its own license.
