# Changelog

All notable changes to `metamorphic_log` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0]

Initial release: the Elixir/Hex client for the `metamorphic-log` transparency-log
engine, as a sibling package to `metamorphic_crypto`, built on precompiled Rust
NIFs (Rustler + `rustler_precompiled`) wrapping the published `metamorphic-log`
crate.

### Added

- **Verification + monitor SDK**, mirroring the browser WASM SDK surface:
  - `MetamorphicLog.Proof` — RFC 6962/9162 inclusion & consistency verification.
  - `MetamorphicLog.Checkpoint` / `MetamorphicLog.Note` — C2SP signed-note and
    tlog-checkpoint parse/verify, with classical Ed25519 and additive hybrid
    post-quantum (ML-DSA + Ed25519) signatures.
  - `MetamorphicLog.Coniks` / `MetamorphicLog.Commitment` — CONIKS lookup/absence
    proof verification and SHA3-512 commitment verification.
  - `MetamorphicLog.Policy` — signed namespace-policy verification and
    declared == observed posture enforcement.
  - `MetamorphicLog.Leaf` — the `mosslet/key-history/v1` canonical leaf encoding,
    entry hash, and RFC 6962 leaf hash.
- **Ingestion primitives** (`MetamorphicLog.Ingest`) — content/token dedup keys,
  tile flush geometry, and Merkle recomputation over tile bytes for an Elixir
  operator pipeline. Sequencing state and tile I/O are intentionally left to the
  BEAM side.
- CPU-bound NIFs (proof/VRF/signature verification, Merkle recomputation) run on
  dirty CPU schedulers; micro-operations run inline.
- **Cross-language byte-parity KAT** (`test/cross_language_kat_test.exs`): the
  NIF reproduces the same locked vectors as the Rust core and WASM SDK
  (`metamorphic-log/tests/cross_language.rs`).

[0.1.0]: https://github.com/moss-piglet/metamorphic_log/releases/tag/v0.1.0
