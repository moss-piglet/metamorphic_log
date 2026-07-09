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
end
