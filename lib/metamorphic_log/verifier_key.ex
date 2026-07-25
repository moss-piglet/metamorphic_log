defmodule MetamorphicLog.VerifierKey do
  @moduledoc """
  C2SP `signed-note` **verifier-key** (`vkey`) encoding.

  A verifier key is the text a relying party pins to recognize and check a
  signer's note/checkpoint signatures:

      <name>+<hex(key_id)>+<base64(type_id || public_key)>

  where `key_id = SHA-256(name || 0x0A || type_id || public_key)[:4]` (big
  endian). These encoders derive the key id and produce the canonical `vkey`
  string for the two supported signature types, so a server can publish the
  `vkey` its clients feed to `MetamorphicLog.Checkpoint.verify/2` and
  `MetamorphicLog.Note.verify/2`.

  Public keys cross the boundary **base64-encoded**.
  """

  alias MetamorphicLog.Native

  @doc """
  Encode a hybrid composite verifier key from a key `name` and the
  metamorphic-crypto composite public key bytes
  (`tag || classical_pk || ml_dsa_pk`, base64).

  This is the public key stored as a namespace's signing key. Returns
  `{:ok, vkey}` or `{:error, reason}` (invalid name or empty key).

  ## Example

      {:ok, vkey} = MetamorphicLog.VerifierKey.encode_hybrid("metamorphic.app/log", pk_b64)

  """
  @spec encode_hybrid(name :: String.t(), public_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def encode_hybrid(name, public_key_b64)
      when is_binary(name) and is_binary(public_key_b64) do
    Native.nif_vkey_encode_hybrid(name, public_key_b64)
  end

  @doc """
  Encode a classical Ed25519 verifier key from a key `name` and a 32-byte public
  key (base64).

  Returns `{:ok, vkey}` or `{:error, reason}` (invalid name or a key that is not
  32 bytes).
  """
  @spec encode_ed25519(name :: String.t(), public_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def encode_ed25519(name, public_key_b64)
      when is_binary(name) and is_binary(public_key_b64) do
    Native.nif_vkey_encode_ed25519(name, public_key_b64)
  end

  @doc """
  Encode a classical Ed25519 (`0x01`) verifier key from a key `name` and the
  Ed25519 half of a `:hybrid`-suite composite public key (base64
  `tag || ed25519_pk || ml_dsa_pk`).

  This is the vkey a stock Ed25519-only C2SP witness needs to verify the
  `0x01` line of a dual-signed checkpoint (`Checkpoint.sign_dual/5`): the
  witness registration bundle for an origin is its hybrid vkey
  (`encode_hybrid/2`) plus this derived vkey. The derivation is deterministic.
  Composite keys without an Ed25519 classical half (matched-suite Ed448/P-521,
  pure-PQ) are rejected.

  Returns `{:ok, vkey}` or `{:error, reason}`.

  ## Example

      {:ok, witness_vkey} =
        MetamorphicLog.VerifierKey.encode_ed25519_from_hybrid("origin/log", composite_pk_b64)

  """
  @spec encode_ed25519_from_hybrid(name :: String.t(), public_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def encode_ed25519_from_hybrid(name, public_key_b64)
      when is_binary(name) and is_binary(public_key_b64) do
    Native.nif_vkey_encode_ed25519_from_hybrid(name, public_key_b64)
  end

  @doc """
  Encode a C2SP `tlog-cosignature` v1 **Ed25519** (`0x04`) verifier key from a
  cosigner `name` (a schema-less URL identifying the witness) and a 32-byte
  Ed25519 public key (base64).

  This is the vkey a log pins to verify a witness's timestamped Ed25519
  cosignature lines (what deployed witnesses emit today). Returns `{:ok, vkey}`
  or `{:error, reason}`.
  """
  @spec encode_cosignature_ed25519(name :: String.t(), public_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def encode_cosignature_ed25519(name, public_key_b64)
      when is_binary(name) and is_binary(public_key_b64) do
    Native.nif_vkey_encode_cosignature_ed25519(name, public_key_b64)
  end

  @doc """
  Encode a C2SP `tlog-cosignature` v1 **ML-DSA-44** (`0x06`) verifier key from
  a cosigner `name` (a schema-less URL identifying the witness) and a 1312-byte
  ML-DSA-44 public key (base64).

  This is the vkey a log pins to verify a witness's post-quantum ML-DSA-44
  cosignature lines (the cosignature spec's recommended type for new
  deployments). Returns `{:ok, vkey}` or `{:error, reason}`.
  """
  @spec encode_cosignature_mldsa44(name :: String.t(), public_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def encode_cosignature_mldsa44(name, public_key_b64)
      when is_binary(name) and is_binary(public_key_b64) do
    Native.nif_vkey_encode_cosignature_mldsa44(name, public_key_b64)
  end
end
