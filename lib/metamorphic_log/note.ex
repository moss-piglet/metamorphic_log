defmodule MetamorphicLog.Note do
  @moduledoc """
  C2SP signed-note verification and signing.

  A signed note is a UTF-8 text body followed by one or more signature lines, as
  defined by the [C2SP signed-note](https://github.com/C2SP/C2SP/blob/main/signed-note.md)
  spec. This engine supports these signature types:

    * **Ed25519** — the classical C2SP signature type.
    * **Metamorphic hybrid** — an additive composite (`ML-DSA` + `Ed25519`,
      strict-AND verify) that wedges post-quantum integrity into the same note
      format. ML-DSA signing is hedged/randomized, so signature *bytes* are not
      reproducible, but verification is fully deterministic.
    * **Witness cosignatures** ([C2SP `tlog-cosignature`](https://c2sp.org/tlog-cosignature)
      v1) — independent witness co-signatures on a checkpoint, in both the
      classical Ed25519 (`0x04`) and post-quantum ML-DSA-44 (`0x06`) flavors.
      Passing a witness's verifier key to `verify/2` counts its cosignature, so
      a checkpoint note can prove it was co-signed by the log **and** one or more
      independent witnesses (split-view protection).

  `verify/2` takes the note text and a list of **trusted verifier keys** (the
  C2SP `name+hash+base64key` encoding). Unknown-key signatures are ignored; a
  signature from a *known* key that fails rejects the whole note.
  """

  alias MetamorphicLog.Native

  @doc """
  Verify `note_text` against `trusted_vkeys`.

  Returns `{:ok, verified_count}` — the number of trusted signatures that
  verified (always ≥ 1 on success) — or `{:error, reason}` (including
  `"no trusted signature"` when none of the trusted keys signed).

  ## Example

      {:ok, 1} = MetamorphicLog.Note.verify(note_text, [vkey])

  """
  @spec verify(note_text :: String.t(), trusted_vkeys :: [String.t()]) ::
          {:ok, non_neg_integer()} | {:error, String.t()}
  def verify(note_text, trusted_vkeys)
      when is_binary(note_text) and is_list(trusted_vkeys) do
    Native.nif_verify_signed_note(note_text, trusted_vkeys)
  end

  @doc """
  Boolean form of `verify/2`. Returns `true` if at least one trusted key signed
  and verified.
  """
  @spec verified?(String.t(), [String.t()]) :: boolean()
  def verified?(note_text, trusted_vkeys) do
    match?({:ok, _}, verify(note_text, trusted_vkeys))
  end

  @doc """
  Sign `text` with an additive hybrid PQ composite secret key, returning the
  complete C2SP signed-note text (body + blank line + the hybrid signature
  line).

  `text` must be the exact note body **ending in a newline**. `name` is the
  C2SP key name; `secret_key_b64` is the base64 metamorphic-crypto composite
  secret key. ML-DSA signing is hedged, so the signature bytes are not
  reproducible — but the verifier key derived from `secret_key_b64`'s public
  half (see `MetamorphicLog.VerifierKey.encode_hybrid/2`) verifies the result
  deterministically.

  Returns `{:ok, note_text}` or `{:error, reason}` (invalid name, undecodable
  secret key, or signing failure).

  ## Example

      {:ok, note} = MetamorphicLog.Note.sign_hybrid("origin/log\\n7\\ncm9vdA==\\n", "origin/log", sk)

  """
  @spec sign_hybrid(text :: String.t(), name :: String.t(), secret_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def sign_hybrid(text, name, secret_key_b64)
      when is_binary(text) and is_binary(name) and is_binary(secret_key_b64) do
    Native.nif_note_sign_hybrid(text, name, secret_key_b64)
  end

  @doc """
  Sign `text` with a raw 32-byte Ed25519 seed (base64), returning the complete
  classical (witness-compatible) C2SP signed-note text.

  `text` must be the exact note body ending in a newline. `name` is the C2SP
  key name; `seed_b64` is the base64 32-byte Ed25519 seed. Returns
  `{:ok, note_text}` or `{:error, reason}` (invalid name or a seed that is not
  32 bytes).
  """
  @spec sign_ed25519(text :: String.t(), name :: String.t(), seed_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def sign_ed25519(text, name, seed_b64)
      when is_binary(text) and is_binary(name) and is_binary(seed_b64) do
    Native.nif_note_sign_ed25519(text, name, seed_b64)
  end

  @doc """
  Produce a C2SP `tlog-cosignature` v1 **Ed25519** (`0x04`) cosignature line
  over `note_text` at `timestamp` (POSIX seconds), from a raw 32-byte Ed25519
  seed (base64).

  This is what a witness emits after verifying a log's consistency: a
  timestamped Ed25519 signature over the domain-separated `cosignature/v1`
  message (header + `time <timestamp>` line + the whole cosigned note body).
  `note_text` must be the exact cosigned note body (the checkpoint text,
  ending in a newline, no signature block); `name` is the cosigner name (a
  schema-less URL identifying the witness).

  Returns `{:ok, line}` — a single `— <name> <base64>` signature line with NO
  trailing newline — or `{:error, reason}`. Newline-terminate and concatenate
  lines to build a cosignature block; verify with the matching
  `VerifierKey.encode_cosignature_ed25519/2` key.

  ## Example

      {:ok, line} =
        MetamorphicLog.Note.sign_cosignature_ed25519(body, "witness.example.com", seed, ts)

      cosig_lines = line <> "\\n"

  """
  @spec sign_cosignature_ed25519(
          note_text :: String.t(),
          name :: String.t(),
          seed_b64 :: String.t(),
          timestamp :: non_neg_integer()
        ) :: {:ok, String.t()} | {:error, String.t()}
  def sign_cosignature_ed25519(note_text, name, seed_b64, timestamp)
      when is_binary(note_text) and is_binary(name) and is_binary(seed_b64) and
             is_integer(timestamp) and timestamp >= 0 do
    Native.nif_note_sign_cosignature_ed25519(note_text, name, seed_b64, timestamp)
  end

  @doc """
  Produce a C2SP `tlog-cosignature` v1 **ML-DSA-44** (`0x06`) cosignature line
  over the checkpoint in `note_text` at `timestamp` (POSIX seconds), from a
  raw 32-byte ML-DSA-44 seed (base64).

  The post-quantum sibling of `sign_cosignature_ed25519/4`: an ML-DSA-44
  signature over the spec's `cosigned_message` struct (label `subtree/v1\\n\\0`,
  cosigner name, timestamp, log origin, subtree bounds `0..size`, root hash),
  which — unlike the Ed25519 type — commits to the cosigner name. `note_text`
  must parse as a checkpoint (its first three lines are origin/size/root).
  ML-DSA signing is hedged, so signature bytes are not reproducible, but
  verification is deterministic.

  Returns `{:ok, line}` (no trailing newline) or `{:error, reason}`. Verify
  with the matching `VerifierKey.encode_cosignature_mldsa44/2` key.
  """
  @spec sign_cosignature_mldsa44(
          note_text :: String.t(),
          name :: String.t(),
          seed_b64 :: String.t(),
          timestamp :: non_neg_integer()
        ) :: {:ok, String.t()} | {:error, String.t()}
  def sign_cosignature_mldsa44(note_text, name, seed_b64, timestamp)
      when is_binary(note_text) and is_binary(name) and is_binary(seed_b64) and
             is_integer(timestamp) and timestamp >= 0 do
    Native.nif_note_sign_cosignature_mldsa44(note_text, name, seed_b64, timestamp)
  end
end
