defmodule MetamorphicLog.Coniks do
  @moduledoc """
  CONIKS key-transparency lookup and absence verification (Layer 3).

  CONIKS lets a relying party verify what value a log binds to an identity —
  or that it binds *none* — without the operator being able to equivocate, and
  without revealing other identities. Lookups are privacy-preserving: the
  identity is blinded through a VRF (RFC 9381 ECVRF over edwards25519 by
  default, suite `0x03`).

  These functions are the **verifier** side and need no directory state — only
  the operator's published `vrf_public` key, the directory `root` (a 64-byte
  SHA3-512 prefix-tree root), the queried `identity`, and the `proof` the
  operator returned.

  All binary arguments are **base64-encoded**; `namespace` is a UTF-8 label
  such as `"mosslet.app"`.
  """

  alias MetamorphicLog.Native

  @doc """
  Verify a **presence** (lookup) proof: that `identity` maps to a value in the
  directory committed by `root`.

  Returns `{:ok, value_b64}` with the bound value on success, or
  `{:error, reason}`.

  ## Example

      {:ok, value} =
        MetamorphicLog.Coniks.verify_lookup(namespace, vrf_public, root, identity, proof)

  """
  @spec verify_lookup(
          namespace :: String.t(),
          vrf_public_b64 :: String.t(),
          root_b64 :: String.t(),
          identity_b64 :: String.t(),
          proof_b64 :: String.t()
        ) :: {:ok, String.t()} | {:error, String.t()}
  def verify_lookup(namespace, vrf_public_b64, root_b64, identity_b64, proof_b64)
      when is_binary(namespace) and is_binary(vrf_public_b64) and is_binary(root_b64) and
             is_binary(identity_b64) and is_binary(proof_b64) do
    Native.nif_coniks_verify_lookup(namespace, vrf_public_b64, root_b64, identity_b64, proof_b64)
  end

  @doc """
  Verify an **absence** proof: that `identity` is *not* bound in the directory
  committed by `root`.

  Returns `:ok` or `{:error, reason}`.

  ## Example

      :ok = MetamorphicLog.Coniks.verify_absence(namespace, vrf_public, root, identity, proof)

  """
  @spec verify_absence(
          namespace :: String.t(),
          vrf_public_b64 :: String.t(),
          root_b64 :: String.t(),
          identity_b64 :: String.t(),
          proof_b64 :: String.t()
        ) :: :ok | {:error, String.t()}
  def verify_absence(namespace, vrf_public_b64, root_b64, identity_b64, proof_b64)
      when is_binary(namespace) and is_binary(vrf_public_b64) and is_binary(root_b64) and
             is_binary(identity_b64) and is_binary(proof_b64) do
    Native.nif_coniks_verify_absence(namespace, vrf_public_b64, root_b64, identity_b64, proof_b64)
  end
end
