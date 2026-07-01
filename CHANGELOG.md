# Changelog

All notable changes to `metamorphic_log` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3]

Supply-chain currency bump. Bumps the wrapped crate dependencies
`metamorphic-log 0.1.4 -> 0.1.5` and `metamorphic-crypto 0.9 -> 0.10`
(published crates only; no `[patch]`/path deps). No canonical byte-format
changes — inclusion/consistency, `key-history/v1`, CONIKS, signed-note/checkpoint,
commitment, policy-v1, KEYTRANS, and ingestion are all unchanged. The wrapped
`metamorphic-crypto 0.10` is additive only (adds a standalone HKDF-SHA512
primitive that is unused here). `p256` stays pinned at `=0.14.0-rc.14`.

## [0.1.2]

Brings the NIF up to parity with the `metamorphic-log` Rust crate **0.1.4**,
adding the Slice 9 **KEYTRANS** (IETF combined-tree directory) verification
surface and the namespace-policy **directory axis**. Bumps the wrapped crate
dependencies `metamorphic-log 0.1.3 -> 0.1.4` and `metamorphic-crypto 0.8 -> 0.9`
(published crates only; no `[patch]`/path deps). No canonical byte-format
changes to any frozen layer — inclusion/consistency, `key-history/v1`, CONIKS,
signed-note/checkpoint, commitment, policy-v1, and ingestion are all unchanged,
and the CONIKS-route policy output is backward-compatible (new keys are
additive).

### Added

- **KEYTRANS verification (`MetamorphicLog.Keytrans`).** Suite-aware,
  relying-party verification of the IETF KEYTRANS combined-tree directory
  (`draft-ietf-keytrans-protocol-04`), mirroring the browser WASM SDK's
  `keytransVerify*Suite` surface. Stateless — recomputes everything from public
  inputs (VRF public key, combined-tree root, label, proof).
  - `verify_search/6` — greatest-version search (§6): the value at a label's
    most recent version, or absence.
  - `verify_fixed_version/6` — fixed-version search (§7).
  - `verify_monitor/6` — monitoring (§8): a downgrade is rejected.
  - `suite_id/1` — the §15.1 `suite_id` for a suite atom.
  - The cipher **suite is always explicit** (no default): `:kt128_sha256_p256`
    (`0x0001`), `:kt128_sha256_ed25519` (`0x0002`) — the on-spec IETF standard
    suites (HMAC-SHA256 commitment) — and `:metamorphic_hybrid_exp` (`0xF000`),
    the private hybrid-PQ suite.
  - **Movable / experimental:** the proof wire is tagged `KEYTRANS_EXP_04` and
    tracks the draft; it is deliberately not byte-frozen. The golden test
    vectors are kept out of the frozen cross-language KAT set.
- **Policy directory axis (`MetamorphicLog.Policy`).**
  - Verified policies now expose `:directory_mode` (`:coniks` | `:keytrans`)
    and `:keytrans_suite` (`:metamorphic_hybrid_exp` | `:kt128_sha256_p256` |
    `:kt128_sha256_ed25519`) alongside the existing posture fields (additive,
    backward-compatible; default to the CONIKS route).
  - `enforce_directory_backend/2` — **declared == observed** for the directory
    backend, accepting a `:coniks` / `:keytrans` atom or a raw `u16` id.

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
