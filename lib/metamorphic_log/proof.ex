defmodule MetamorphicLog.Proof do
  @moduledoc """
  RFC 6962 / 9162 Merkle **inclusion** and **consistency** proof verification.

  Thin, idiomatic wrappers over the audited `metamorphic-log` Rust core — the
  same code path used by the browser WASM SDK, so a proof that verifies here
  verifies identically in the browser and on the server.

  ## Encoding

  Hashes, roots, and each proof node are **base64-encoded** binaries (standard
  padded alphabet). A proof is a list of base64 strings, each a 32-byte
  SHA-256 node hash, ordered as produced by the log.

  ## Return shape

  The `verify_*` functions return `:ok` when the proof checks out, or
  `{:error, reason}` for either a failed check or malformed input — faithful to
  the engine's `Result`. The `valid_*?/n` predicates collapse that to a boolean
  for call sites that only need a yes/no.

  ## Scheduling

  Verification runs on a dirty CPU scheduler, so a burst of proof checks won't
  block the BEAM's normal schedulers.
  """

  alias MetamorphicLog.Native

  @doc """
  Verify that `leaf_hash` is included at `index` in a tree of `size` leaves
  whose root is `root`.

  `proof` is a list of base64-encoded sibling hashes. Returns `:ok` or
  `{:error, reason}`.

  ## Example

      :ok = MetamorphicLog.Proof.verify_inclusion(index, size, leaf_hash, proof, root)

  """
  @spec verify_inclusion(
          index :: non_neg_integer(),
          size :: non_neg_integer(),
          leaf_hash_b64 :: String.t(),
          proof_b64 :: [String.t()],
          root_b64 :: String.t()
        ) :: :ok | {:error, String.t()}
  def verify_inclusion(index, size, leaf_hash_b64, proof_b64, root_b64)
      when is_integer(index) and is_integer(size) and is_binary(leaf_hash_b64) and
             is_list(proof_b64) and is_binary(root_b64) do
    Native.nif_verify_inclusion(index, size, leaf_hash_b64, proof_b64, root_b64)
  end

  @doc """
  Boolean form of `verify_inclusion/5`. Returns `true` only on a valid proof.
  """
  @spec valid_inclusion?(
          non_neg_integer(),
          non_neg_integer(),
          String.t(),
          [String.t()],
          String.t()
        ) :: boolean()
  def valid_inclusion?(index, size, leaf_hash_b64, proof_b64, root_b64) do
    verify_inclusion(index, size, leaf_hash_b64, proof_b64, root_b64) == :ok
  end

  @doc """
  Verify that a log of `root2` (`size2` leaves) is a consistent, append-only
  extension of an earlier log of `root1` (`size1` leaves).

  `proof` is a list of base64-encoded hashes. Returns `:ok` or
  `{:error, reason}`.

  ## Example

      :ok = MetamorphicLog.Proof.verify_consistency(size1, size2, proof, root1, root2)

  """
  @spec verify_consistency(
          size1 :: non_neg_integer(),
          size2 :: non_neg_integer(),
          proof_b64 :: [String.t()],
          root1_b64 :: String.t(),
          root2_b64 :: String.t()
        ) :: :ok | {:error, String.t()}
  def verify_consistency(size1, size2, proof_b64, root1_b64, root2_b64)
      when is_integer(size1) and is_integer(size2) and is_list(proof_b64) and
             is_binary(root1_b64) and is_binary(root2_b64) do
    Native.nif_verify_consistency(size1, size2, proof_b64, root1_b64, root2_b64)
  end

  @doc """
  Boolean form of `verify_consistency/5`. Returns `true` only on a valid proof.
  """
  @spec valid_consistency?(
          non_neg_integer(),
          non_neg_integer(),
          [String.t()],
          String.t(),
          String.t()
        ) :: boolean()
  def valid_consistency?(size1, size2, proof_b64, root1_b64, root2_b64) do
    verify_consistency(size1, size2, proof_b64, root1_b64, root2_b64) == :ok
  end
end
