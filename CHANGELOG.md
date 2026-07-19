# Changelog

All notable changes to `metamorphic_log` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.8]

Adds the **server-side CONIKS directory construction** surface (the operator /
prover counterpart to the existing verify-only CONIKS APIs), so an operator can
build a per-namespace directory, append identity→value entries, publish its
root, and produce presence/absence proofs — all through the audited Rust core.
Additive; no wire-format or existing-API changes.

### Added

- `MetamorphicLog.Coniks.generate_vrf_key/0` — generate a fresh classical
  (ECVRF-edwards25519, suite `0x03`) VRF keypair, returning `{:ok, {secret_b64,
  public_b64}}`. The secret is per-namespace operator infrastructure.
- `MetamorphicLog.Coniks.directory_open/2` — open an opaque, stateful directory
  resource from a namespace + VRF secret. The directory is held as a Rust-side
  `RwLock<ConiksDirectory>`: concurrent reads, serialized appends. Built once
  and updated incrementally rather than rebuilt per request.
- `MetamorphicLog.Coniks.insert/3` — insert/replace an identity's committed
  value at its VRF-derived index (write path).
- `MetamorphicLog.Coniks.root/1` — the 64-byte SHA3-512 prefix-tree root.
- `MetamorphicLog.Coniks.lookup/2` — produce a presence
  (`{:ok, {:present, value_b64, proof_b64}}`) or absence
  (`{:ok, {:absent, proof_b64}}`) proof against the current root; the proof
  verifies via the existing `verify_lookup/5` / `verify_absence/5`.
- `MetamorphicLog.Coniks.vrf_public/1` — the published VRF public key.

### Added (KEYTRANS construction — experimental)

- `MetamorphicLog.Keytrans.generate_vrf_key/1`, `directory_open/3`, `update/5`,
  `combined_root/1`, `prove_search/2`, and `directory_vrf_public/1` — the
  operator / prover counterpart to the verify-only KEYTRANS APIs, mirroring the
  CONIKS construction resource. An operator opens a per-namespace combined-tree
  directory from a VRF secret on an explicit suite, appends label versions,
  publishes its combined-tree root, and produces greatest-version search proofs
  (`{:ok, {:present, value_b64, proof_b64}}` / `{:ok, {:absent, proof_b64}}`)
  that verify via the existing `verify_search/6`. Held as a Rust-side
  `RwLock<KeytransDirectory>`: concurrent reads, serialized appends. Suite-aware
  throughout (the §15.1 `suite_id` selects the VRF, commitment width, and
  opening length; nothing is hardcoded).
- **Experimental / movable**: the KEYTRANS wire (`draft-ietf-keytrans-protocol-04`)
  is not byte-frozen. Directory-lookup serving launches CONIKS-only and flags
  KEYTRANS as unavailable; this surface backs the follow-up path.

### Changed

- Bump the native `metamorphic-log` core dependency 0.1.11 → 0.2.1. 0.2.0 adds
  the `Send + Sync` bound on `vrf::Vrf` required to own a `ConiksDirectory` /
  `KeytransDirectory` (each holding a `Box<dyn Vrf>`) inside a BEAM resource;
  0.2.1 adds the incremental CONIKS tree-hash cache (O(1) amortized root,
  ~O(depth) lookup) with byte-identical proofs. No frozen format, KAT vector, or
  existing verification output changes.

## [0.1.7]

Adds a **context-parameterized key-history entry hash**, so any application can
produce a branded transparency-log leaf (for example `mosskeys/key-history/v1`)
through the audited byte discipline instead of inheriting the reference
`mosslet/key-history/v1` instance or hand-rolling the hash. Additive — the
frozen `mosslet/key-history/v1` vectors are byte-for-byte unchanged, and the
canonical bytes plus RFC 6962 leaf hash stay brand-independent.

### Added

- `MetamorphicLog.Leaf.key_history_entry_hash_with_context/2` (and its `!`
  variant) — compute an intra-chain entry hash under your own
  `<namespace>/<record-type>/v<major>` label. This is now the **recommended**
  way to compute a key-history `entry_hash`: branding with your own namespace
  domain-separates your hashes and lets auditors tell whose key history a chain
  is. Passing `"mosslet/key-history/v1"` reproduces
  `key_history_v1_entry_hash/1` byte-for-byte; a malformed label returns
  `{:error, reason}`. Backed by the new `entry_hash_with_context` surface in the
  native core.

### Changed

- Bump the native `metamorphic-log` core dependency 0.1.10 → 0.1.11, which
  exposes the context-parameterized key-history entry point across all bindings.
  The `key_history_v1_*` functions and their KATs are unchanged.

## [0.1.6]

Supply-chain bump propagating the upstream ML-DSA signing-stack hardening down
to the primitives layer. No public API, wire-format, or behavioural changes —
every proof, CONIKS, KEYTRANS, commitment, ingestion, and signing path is
byte-for-byte identical to 0.1.5.

### Changed

- Bump the native `metamorphic-log` core dependency 0.1.9 → 0.1.10 and
  `metamorphic-crypto` 0.10.2 → 0.10.5, pulling in the shared native signing
  guard and the 8 MiB WASM shadow-stack linker bump at the source.
- **Dedupe the signing-stack guard.** The locally open-coded `on_signing_stack`
  helper in the NIF is replaced by the shared, audited generic
  `metamorphic_crypto::on_signing_stack`, which the crypto core now exports (a
  32 MiB scoped worker thread that joins and resumes any unwind). Behaviour is
  unchanged — the hybrid signing NIFs (`nif_note_sign_hybrid`,
  `nif_checkpoint_sign_hybrid`, `nif_signed_policy_sign`) still run ML-DSA off
  the dirty scheduler on an ample stack, so callers need no `+sssdcpu` tuning.
  `#![forbid(unsafe_code)]` is retained.
- Bump the `:test`-only `metamorphic_crypto` Hex dependency `~> 0.8.1` → `~> 0.8.2`
  so the test suite (including the SIGBUS regression) resolves against the
  hardened NIF release.

## [0.1.5]

Adds the **signing (producer) surface** to complement the existing verification
APIs, so operators (checkpoint publishers, witnesses, policy authors) can
produce C2SP artifacts server-side from a metamorphic-crypto composite key or a
raw Ed25519 seed. Additive — no canonical byte-format changes; every existing
verification, proof, CONIKS, KEYTRANS, commitment, and ingestion path is
unchanged.

### Added

- `MetamorphicLog.VerifierKey.encode_hybrid/2` and `encode_ed25519/2` — derive
  the canonical C2SP `vkey` text (`<name>+<hex(key_id)>+<base64(type_id ||
  public_key)>`) from a stored public key, ready to feed
  `Checkpoint.verify/2` / `Note.verify/2`.
- `MetamorphicLog.Note.sign_hybrid/3` and `sign_ed25519/3` — produce a signed
  note over an arbitrary body.
- `MetamorphicLog.Checkpoint.sign_hybrid/5` — sign an `origin`/`size`/`root`
  checkpoint head as a hybrid post-quantum signed note.
- `MetamorphicLog.Policy.sign/2` — sign a namespace policy (CONIKS or KEYTRANS
  directory axis) into the canonical `SignedPolicy` envelope, with atom→string
  enum validation ahead of the NIF boundary.

  ML-DSA signing is hedged (randomized): signature bytes are not reproducible,
  but the derived verifier key verifies deterministically.

### Fixed

- **Dirty-scheduler stack overflow on hybrid signing.** ML-DSA's hedged signing
  path allocates large intermediate lattice matrices on the stack, overflowing
  the BEAM dirty-CPU scheduler thread's default stack (`+sssdcpu`, ~320 KB) and
  crashing the VM with SIGBUS. The signing NIFs now run the core operation on a
  dedicated thread with an ample (32 MiB) stack and block the dirty scheduler on
  the join, so callers need no `+sssdcpu` tuning in `vm.args`. Ed25519 signing
  and all verification paths were unaffected.

### Changed

- Bumps the wrapped crate dependency `metamorphic-log 0.1.6 -> 0.1.9` (adds the
  `checkpoint::sign_checkpoint_hybrid` convenience and the note/vkey/policy
  signing primitives consumed here). `metamorphic-crypto` stays at `0.10.2`.
- Bumps `rustler 0.37 -> 0.38` and raises the NIF crate MSRV `1.85 -> 1.91`
  (required by `metamorphic-crypto`'s toolchain). Adds `metamorphic_crypto
  ~> 0.8.1` as a **test-only** dependency for producer↔verifier round-trips.

## [0.1.4]

Supply-chain / dependency maintenance release. Bumps the wrapped crate
dependencies `metamorphic-log 0.1.5 -> 0.1.6` and
`metamorphic-crypto 0.10.0 -> 0.10.2`, refreshing the NIF `Cargo.lock` to pull
in the transitive **`cmov` 0.5.3 -> 0.5.4** security fix (RustSec
**GHSA-3rjw-m598-pq24 / CVE-2026-50185**, aarch64 `Cmov`/`CmovEq` correctness),
`aes-gcm` 0.11.0 (rc -> stable), and `anyhow` 1.0.103 (RUSTSEC-2026-0190,
build-tooling only). Dependency-only — **no canonical byte-format changes**;
inclusion/consistency, `key-history/v1`, CONIKS, signed-note/checkpoint,
commitment, policy-v1, KEYTRANS, and ingestion are all unchanged. Precompiled
NIFs rebuilt for all targets.

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
