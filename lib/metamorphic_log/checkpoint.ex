defmodule MetamorphicLog.Checkpoint do
  @moduledoc """
  Transparency-log checkpoints (signed tree heads), in the
  [C2SP tlog-checkpoint](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md)
  format carried inside a `MetamorphicLog.Note`.

  A checkpoint commits to a log's `origin`, `size`, and Merkle `root`. Verifying
  one against trusted keys, then checking inclusion/consistency proofs *against
  that verified checkpoint*, is the core monitor/auditor workflow.
  """

  alias MetamorphicLog.Native

  @typedoc "A parsed/verified checkpoint. `root` is base64-encoded."
  @type t :: %__MODULE__{
          origin: String.t(),
          size: non_neg_integer(),
          root: String.t(),
          extensions: [String.t()]
        }

  defstruct [:origin, :size, :root, extensions: []]

  @doc """
  Parse an **unverified** checkpoint body (no signature check).

  Use this only when the signature has already been established out of band;
  otherwise prefer `verify/2`. Returns `{:ok, %Checkpoint{}}` or
  `{:error, reason}`.
  """
  @spec parse(body_text :: String.t()) :: {:ok, t()} | {:error, String.t()}
  def parse(body_text) when is_binary(body_text) do
    body_text |> Native.nif_checkpoint_parse() |> to_struct()
  end

  @doc """
  Verify a signed-note `note_text` against `trusted_vkeys` and return the
  enclosed checkpoint.

  Returns `{:ok, %Checkpoint{}}` or `{:error, reason}`.

  ## Example

      {:ok, %MetamorphicLog.Checkpoint{size: size, root: root}} =
        MetamorphicLog.Checkpoint.verify(note_text, [vkey])

  """
  @spec verify(note_text :: String.t(), trusted_vkeys :: [String.t()]) ::
          {:ok, t()} | {:error, String.t()}
  def verify(note_text, trusted_vkeys)
      when is_binary(note_text) and is_list(trusted_vkeys) do
    note_text |> Native.nif_checkpoint_verify(trusted_vkeys) |> to_struct()
  end

  @doc """
  Verify `note_text` against `trusted_vkeys`, then verify that `leaf_hash` is
  included at `leaf_index` under that checkpoint's root.

  `proof` is a list of base64-encoded sibling hashes. Returns `:ok` or
  `{:error, reason}`.
  """
  @spec verify_inclusion(
          note_text :: String.t(),
          trusted_vkeys :: [String.t()],
          leaf_index :: non_neg_integer(),
          leaf_hash_b64 :: String.t(),
          proof_b64 :: [String.t()]
        ) :: :ok | {:error, String.t()}
  def verify_inclusion(note_text, trusted_vkeys, leaf_index, leaf_hash_b64, proof_b64)
      when is_binary(note_text) and is_list(trusted_vkeys) and is_integer(leaf_index) and
             is_binary(leaf_hash_b64) and is_list(proof_b64) do
    Native.nif_checkpoint_verify_inclusion(
      note_text,
      trusted_vkeys,
      leaf_index,
      leaf_hash_b64,
      proof_b64
    )
  end

  @doc """
  Verify both `older_note` and `newer_note` against `trusted_vkeys`, then verify
  that the newer checkpoint is a consistent extension of the older one.

  `proof` is a list of base64-encoded hashes. Returns `:ok` or
  `{:error, reason}`.
  """
  @spec verify_consistency(
          older_note :: String.t(),
          newer_note :: String.t(),
          trusted_vkeys :: [String.t()],
          proof_b64 :: [String.t()]
        ) :: :ok | {:error, String.t()}
  def verify_consistency(older_note, newer_note, trusted_vkeys, proof_b64)
      when is_binary(older_note) and is_binary(newer_note) and is_list(trusted_vkeys) and
             is_list(proof_b64) do
    Native.nif_checkpoint_verify_consistency(older_note, newer_note, trusted_vkeys, proof_b64)
  end

  @doc """
  Build a checkpoint body and sign it with a hybrid PQ composite secret key in
  one call, returning the complete C2SP signed-note text ready to publish.

  `origin` is the log identity line; `size` the tree size; `root_b64` the
  base64 of the exactly 32-byte RFC 6962 root at `size`; `name` the C2SP key
  name (usually the origin); `secret_key_b64` the base64 composite secret key.

  This is the one-call producer path for a checkpoint publisher: it shares the
  core's `Checkpoint` + `sign_hybrid` code path, so it never hand-assembles the
  byte layout. The verifier key derived from `secret_key_b64`'s public half
  (`MetamorphicLog.VerifierKey.encode_hybrid/2`) verifies the produced note via
  `verify/2`.

  Returns `{:ok, note_text}` or `{:error, reason}` (malformed checkpoint —
  empty origin or non-32-byte root — or a signing failure).

  ## Example

      {:ok, note} =
        MetamorphicLog.Checkpoint.sign_hybrid("origin/log", 10, root_b64, "origin/log", sk)

  """
  @spec sign_hybrid(
          origin :: String.t(),
          size :: non_neg_integer(),
          root_b64 :: String.t(),
          name :: String.t(),
          secret_key_b64 :: String.t()
        ) :: {:ok, String.t()} | {:error, String.t()}
  def sign_hybrid(origin, size, root_b64, name, secret_key_b64)
      when is_binary(origin) and is_integer(size) and size >= 0 and is_binary(root_b64) and
             is_binary(name) and is_binary(secret_key_b64) do
    Native.nif_checkpoint_sign_hybrid(origin, size, root_b64, name, secret_key_b64)
  end

  # ─── Internal ────────────────────────────────────────────────────────────

  defp to_struct({:ok, {origin, size, root, extensions}}) do
    {:ok, %__MODULE__{origin: origin, size: size, root: root, extensions: extensions}}
  end

  defp to_struct({:error, _reason} = error), do: error
end
