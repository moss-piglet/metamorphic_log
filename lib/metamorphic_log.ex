defmodule MetamorphicLog do
  @moduledoc """
  Elixir client for the **metamorphic-log** transparency-log engine.

  `MetamorphicLog` wraps the audited `metamorphic-log` Rust crate via precompiled
  Rust NIFs — no Rust toolchain, no C compiler, no system packages required. It
  surfaces the engine's **verification + monitor SDK** plus the deterministic
  **ingestion primitives**, byte-for-byte compatible with the browser WASM SDK
  and the native core.

  > #### Verification-focused {: .info}
  >
  > This package verifies and recomputes; it does not run a hosted log. All
  > cryptography is the single-source-of-truth `metamorphic-crypto` core.

  ## Modules

  - `MetamorphicLog.Proof` — RFC 6962/9162 inclusion & consistency proofs
  - `MetamorphicLog.Checkpoint` — signed tree heads (parse/verify + proofs)
  - `MetamorphicLog.Note` — C2SP signed-note verification (Ed25519 + hybrid PQ)
  - `MetamorphicLog.Coniks` — CONIKS key-transparency lookup/absence proofs
  - `MetamorphicLog.Commitment` — SHA3-512 commitment verification
  - `MetamorphicLog.Policy` — signed namespace policy + declared==observed
  - `MetamorphicLog.Leaf` — canonical `mosslet/key-history/v1` leaf encoding
  - `MetamorphicLog.Ingest` — dedup keys, flush geometry, Merkle recomputation

  ## Wire format

  Binary values (hashes, roots, proof nodes, keys, openings) are **base64-encoded**
  strings; checkpoint/note bodies and verifier keys are UTF-8 text. This matches
  the WASM SDK and is what makes cross-target digests identical.

  ## Quick start

      # Verify an inclusion proof against a verified checkpoint
      {:ok, %MetamorphicLog.Checkpoint{}} =
        MetamorphicLog.Checkpoint.verify(note_text, [vkey])

      :ok =
        MetamorphicLog.Checkpoint.verify_inclusion(
          note_text, [vkey], leaf_index, leaf_hash, proof
        )

  """

  alias MetamorphicLog.Proof

  @doc """
  Convenience delegate for `MetamorphicLog.Proof.verify_inclusion/5`.
  """
  @spec verify_inclusion(
          non_neg_integer(),
          non_neg_integer(),
          String.t(),
          [String.t()],
          String.t()
        ) :: :ok | {:error, String.t()}
  defdelegate verify_inclusion(index, size, leaf_hash_b64, proof_b64, root_b64), to: Proof

  @doc """
  Convenience delegate for `MetamorphicLog.Proof.verify_consistency/5`.
  """
  @spec verify_consistency(
          non_neg_integer(),
          non_neg_integer(),
          [String.t()],
          String.t(),
          String.t()
        ) :: :ok | {:error, String.t()}
  defdelegate verify_consistency(size1, size2, proof_b64, root1_b64, root2_b64), to: Proof
end
