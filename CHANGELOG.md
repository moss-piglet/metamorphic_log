# Changelog

All notable changes to `metamorphic_log` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1]

Brings the NIF up to parity with the `metamorphic-log` Rust crate **0.1.3**,
adding the Slice 8 **anchoring / attestation** surface (the crate's first
post-v0.1 slice). No canonical byte-format changes to any audited layer; the
existing verification, CONIKS, policy, and ingestion surfaces are unchanged.
Bumps the wrapped crate dependency `0.1.2 -> 0.1.3`.

### Added

- **Backend-agnostic anchoring (`MetamorphicLog.Anchor`).** Format + verification
  for committing a checkpoint's signed tree head to an external,
  hard-to-equivocate medium (chain, RFC 3161 notary, WORM storage, another log),
  byte-identical to the native core and WASM SDK. Deliberately I/O-free — the
  medium client, cadence, fees, and confirmation depth stay in the operator
  layer.
  - `record_canonical_bytes/6` / `parse_record/1` — the canonical, byte-locked
    `AnchorRecord` binding a checkpoint head (`origin` / `size` / `root_hash`) to
    an opaque `locator` and an agnostic `medium` tag, with a self-describing
    safe-menu commitment algorithm (`"sha3_512"` in v0.1).
  - `anchor_commitment/1` — the fixed-size, medium-independent commitment an
    operator publishes to (and re-fetches from) the medium.
  - `rfc6962_leaf_hash/1` — the record's Layer-0 leaf hash, so attestations may
    themselves be logged.
  - `verify_anchored/4` — the log-side third-party audit that an attestation
    binds a checkpoint and that successive anchored heads are append-only
    consistent (RFC 9162), trusting neither operator nor medium.
  - `verify_commitment/2` — the medium-side counterpart: bytes fetched from the
    medium equal the recomputed commitment. The Rust `CommitmentSink` trait and
    its I/O bridges are intentionally **not** wrapped — that backend belongs on
    the BEAM side.
- Docs: HexDocs badge in the README and an **Anchoring** module group.

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

[0.1.1]: https://github.com/moss-piglet/metamorphic_log/releases/tag/v0.1.1
[0.1.0]: https://github.com/moss-piglet/metamorphic_log/releases/tag/v0.1.0
