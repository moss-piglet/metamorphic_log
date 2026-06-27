# Verification guide

This guide walks through the end-to-end **monitor / auditor** workflow with
`metamorphic_log`: given material published by a transparency log, independently
verify it on the server — byte-identically to the browser and the native core.

All binary values are **base64-encoded** strings; checkpoint/note bodies and
verifier keys are UTF-8 text.

## 1. Trust a verifier key

A log (and any co-signing witnesses) publishes one or more **verifier keys** in
the C2SP `name+hash+base64key` encoding. You decide which to trust:

```elixir
trusted = [log_vkey, witness_vkey]
```

Two signature types are supported transparently:

- **Ed25519** — the classical C2SP type.
- **Metamorphic hybrid** — ML-DSA + Ed25519 (strict-AND), wedging post-quantum
  integrity into the same note format.

## 2. Verify a checkpoint (signed tree head)

```elixir
{:ok, %MetamorphicLog.Checkpoint{origin: origin, size: size, root: root}} =
  MetamorphicLog.Checkpoint.verify(note_text, trusted)
```

`verify/2` rejects the note unless a *trusted* key signed it. Unknown-key
signatures are ignored; a known key that fails to verify rejects the note.

## 3. Verify inclusion against the verified checkpoint

```elixir
:ok =
  MetamorphicLog.Checkpoint.verify_inclusion(
    note_text, trusted, leaf_index, leaf_hash, proof
  )
```

`proof` is a list of base64 sibling hashes. For the `mosslet/key-history/v1`
record type, compute the `leaf_hash` from the entry:

```elixir
{:ok, leaf_hash} = MetamorphicLog.Leaf.key_history_v1_rfc6962_leaf_hash(entry)
```

## 4. Verify consistency (append-only) between two checkpoints

```elixir
:ok =
  MetamorphicLog.Checkpoint.verify_consistency(
    older_note, newer_note, trusted, consistency_proof
  )
```

This is the core anti-equivocation check a monitor runs as the log grows.

## 5. Enforce the namespace policy (declared == observed)

A namespace publishes a **signed policy** declaring its posture. Verify it, then
assert that what you *observe* matches what the policy *declares*:

```elixir
{:ok, policy} = MetamorphicLog.Policy.verify(signed_policy)

# The checkpoint signing key must match the declared posture
:ok = MetamorphicLog.Policy.enforce_checkpoint_signing_key(signed_policy, signing_pub)

# The observed VRF suite / commitment hash must match the declaration
:ok = MetamorphicLog.Policy.enforce_vrf_suite_id(signed_policy, 0x03)
:ok = MetamorphicLog.Policy.enforce_commitment_hash(signed_policy, :sha3_256)
```

This stops an operator from silently downgrading the cryptographic posture.

## 6. Verify CONIKS key-transparency answers

Given the operator's published VRF public key and directory root, verify what a
namespace binds to an identity — or that it binds nothing — without learning
about other identities:

```elixir
{:ok, value} =
  MetamorphicLog.Coniks.verify_lookup(namespace, vrf_public, root, identity, proof)

:ok =
  MetamorphicLog.Coniks.verify_absence(namespace, vrf_public, root, identity, proof)
```

## Cross-target parity

Every function above computes byte-identically to the native Rust core and the
browser WASM SDK; the package's cross-language byte-parity KAT
(`test/cross_language_kat_test.exs`) locks this against the same vectors used by
the engine. That is what lets a log produced by browser clients be recomputed
and audited, unchanged, by an Elixir monitor.
