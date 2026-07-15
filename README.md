# metamorphic_log

[![CI](https://github.com/moss-piglet/metamorphic_log/actions/workflows/ci.yml/badge.svg)](https://github.com/moss-piglet/metamorphic_log/actions/workflows/ci.yml)
[![Hex.pm](https://img.shields.io/hexpm/v/metamorphic_log.svg)](https://hex.pm/packages/metamorphic_log)
[![Hexdocs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://metamorphic-log.hexdocs.pm/MetamorphicLog.html)

Elixir client for the [**metamorphic-log**](https://github.com/moss-piglet/metamorphic-log)
transparency-log engine. It surfaces the engine's **verification + monitor SDK**
and its deterministic **ingestion primitives** to Elixir/Phoenix, powered by
precompiled Rust NIFs — **no Rust toolchain, no C compiler, no system packages
required**.

Everything here computes **byte-for-byte identically** to the engine's native
Rust core and its browser WebAssembly SDK, because all three are thin shells
over the same audited [`metamorphic-crypto`](https://github.com/moss-piglet/metamorphic-crypto)
and `metamorphic-log` crates. A log built by browser clients can therefore be
recomputed and verified, unchanged, on the server.

## What it does

- **Inclusion & consistency proofs** — RFC 6962 / 9162 Merkle proof
  verification (`MetamorphicLog.Proof`).
- **Checkpoints & signed notes** — C2SP signed-note and tlog-checkpoint
  parsing/verification with both classical **Ed25519** and an **additive
  hybrid post-quantum** (ML-DSA + Ed25519) signature type
  (`MetamorphicLog.Checkpoint`, `MetamorphicLog.Note`).
- **CONIKS key transparency** — privacy-preserving lookup/absence proof
  verification over an ECVRF-blinded directory, with SHA3-512 commitments
  (`MetamorphicLog.Coniks`, `MetamorphicLog.Commitment`).
- **KEYTRANS key transparency** *(experimental)* — suite-aware verification of
  the IETF combined-tree directory: greatest-version search, fixed-version
  search, and monitoring, across the on-spec IETF standard suites
  (`KT_128_SHA256_P256`, `KT_128_SHA256_Ed25519`) and a private hybrid-PQ suite
  (`MetamorphicLog.Keytrans`). The proof wire is **movable** — it tracks
  `draft-ietf-keytrans-protocol` and is not byte-frozen.
- **Namespace policy** — signed, in-log posture (suite/level/commitment/VRF
  mode, plus the CONIKS-vs-KEYTRANS directory route and its suite) verification
  and **declared == observed** enforcement, including the directory backend
  (`MetamorphicLog.Policy`).
- **Canonical leaves** — key-history canonical encoding and hashes
  (`MetamorphicLog.Leaf`). Brand your own chain with a
  `<namespace>/key-history/v1` label via `key_history_entry_hash_with_context/2`
  (recommended); `mosslet/key-history/v1` is the frozen reference instance.
- **Ingestion primitives** — content dedup keys, tile flush geometry, and
  Merkle recomputation for an Elixir operator pipeline
  (`MetamorphicLog.Ingest`).

## Installation

```elixir
def deps do
  [
    {:metamorphic_log, "~> 0.1"}
  ]
end
```

A precompiled NIF is downloaded for your platform on first build. To build the
NIF from source instead (requires a Rust toolchain), set
`METAMORPHIC_LOG_BUILD=true`.

## Quick start

```elixir
# Verify a checkpoint (signed tree head) against trusted verifier keys
{:ok, checkpoint} = MetamorphicLog.Checkpoint.verify(note_text, [vkey])

# Then verify that a leaf is included under that verified checkpoint
:ok =
  MetamorphicLog.Checkpoint.verify_inclusion(
    note_text, [vkey], leaf_index, leaf_hash, proof
  )

# Verify a namespace policy and enforce declared == observed posture
{:ok, %MetamorphicLog.Policy{commitment_hash: :sha3_256}} =
  MetamorphicLog.Policy.verify(signed_policy)

:ok = MetamorphicLog.Policy.enforce_vrf_suite_id(signed_policy, 0x03)

# Verify an (experimental) KEYTRANS search proof under an explicit suite
{:ok, {:present, value_b64}} =
  MetamorphicLog.Keytrans.verify_search(
    :kt128_sha256_p256, context, vrf_public, root, label, proof
  )
```

## Wire format

Binary values (hashes, roots, proof nodes, keys, openings) cross the API as
**base64-encoded** strings (standard padded alphabet); checkpoint/note bodies
and verifier keys are UTF-8 text. This matches the browser WASM SDK and is what
makes cross-target digests identical. Use `Base.encode64/1` / `Base.decode64/1`
at your application boundary.

See the [verification guide](docs/verification-guide.md) for the end-to-end
monitor workflow.

## Performance & the BEAM

CPU-bound work — proof verification, CONIKS VRF verification, signature
verification (Ed25519 + ML-DSA), and Merkle recomputation — runs on Erlang
**dirty CPU schedulers**, so bursts of verification never block the normal
schedulers. Genuine micro-operations (canonical framing, single-hash leaf and
dedup digests, parsing, flush geometry) run inline.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at
your option.
