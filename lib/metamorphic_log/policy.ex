defmodule MetamorphicLog.Policy do
  @moduledoc """
  Signed **namespace policy** verification and declared-vs-observed enforcement.

  A namespace policy is a signed, in-log, versioned record declaring the
  cryptographic posture a namespace operates under: checkpoint signature suite
  and security level, the CONIKS commitment hash, and the VRF mode. Because the
  policy is itself a log leaf, the posture is auditable and tamper-evident.

  `verify/1` checks the policy's self-signature and returns the declared
  posture. The `enforce_*` functions then assert that an **observed** artifact
  (a checkpoint signing key, a checkpoint signature, a VRF suite id, or a
  commitment hash) matches what the verified policy **declares** — the
  "declared == observed" invariant that stops an operator from silently
  downgrading.

  The signed policy envelope is **base64-encoded**.
  """

  alias MetamorphicLog.Native

  @typedoc """
  A verified namespace policy.

  * `:security_level` — `:cat3` | `:cat5`
  * `:checkpoint_suite` — `:hybrid` | `:hybrid_matched` | `:pure_cnsa2`
  * `:commitment_hash` — `:sha3_256` | `:sha3_512`
  * `:vrf_mode` — `:classical` | `:hybrid_output` | `:pure_pq_experimental`
  * `:policy_hash`, `:rfc6962_leaf_hash` — base64-encoded
  """
  @type t :: %__MODULE__{
          namespace: String.t(),
          policy_schema_version: non_neg_integer(),
          security_level: :cat3 | :cat5,
          checkpoint_suite: :hybrid | :hybrid_matched | :pure_cnsa2,
          commitment_hash: :sha3_256 | :sha3_512,
          vrf_mode: :classical | :hybrid_output | :pure_pq_experimental,
          effective_from: non_neg_integer(),
          created_at: non_neg_integer(),
          policy_hash: String.t(),
          rfc6962_leaf_hash: String.t()
        }

  defstruct [
    :namespace,
    :policy_schema_version,
    :security_level,
    :checkpoint_suite,
    :commitment_hash,
    :vrf_mode,
    :effective_from,
    :created_at,
    :policy_hash,
    :rfc6962_leaf_hash
  ]

  @doc """
  Verify a signed policy envelope and return the declared posture as a
  `%MetamorphicLog.Policy{}` struct.

  Returns `{:ok, %Policy{}}` or `{:error, reason}`.

  ## Example

      {:ok, %MetamorphicLog.Policy{checkpoint_suite: :hybrid}} =
        MetamorphicLog.Policy.verify(signed_b64)

  """
  @spec verify(signed_b64 :: String.t()) :: {:ok, t()} | {:error, String.t()}
  def verify(signed_b64) when is_binary(signed_b64) do
    case Native.nif_signed_policy_verify(signed_b64) do
      {:ok, {{namespace, schema_version, level, suite, commit_hash}, {vrf, eff, created, ph, lh}}} ->
        {:ok,
         %__MODULE__{
           namespace: namespace,
           policy_schema_version: schema_version,
           security_level: security_level(level),
           checkpoint_suite: checkpoint_suite(suite),
           commitment_hash: commitment_hash(commit_hash),
           vrf_mode: vrf_mode(vrf),
           effective_from: eff,
           created_at: created,
           policy_hash: ph,
           rfc6962_leaf_hash: lh
         }}

      {:error, _reason} = error ->
        error
    end
  end

  defp security_level("cat3"), do: :cat3
  defp security_level("cat5"), do: :cat5

  defp checkpoint_suite("hybrid"), do: :hybrid
  defp checkpoint_suite("hybrid_matched"), do: :hybrid_matched
  defp checkpoint_suite("pure_cnsa2"), do: :pure_cnsa2

  defp commitment_hash("sha3_256"), do: :sha3_256
  defp commitment_hash("sha3_512"), do: :sha3_512

  defp vrf_mode("classical"), do: :classical
  defp vrf_mode("hybrid_output"), do: :hybrid_output
  defp vrf_mode("pure_pq_experimental"), do: :pure_pq_experimental

  @doc """
  Enforce that a checkpoint signing key (`public_key_b64`) matches the verified
  policy's declared checkpoint posture. Returns `:ok` or `{:error, reason}`.
  """
  @spec enforce_checkpoint_signing_key(String.t(), String.t()) :: :ok | {:error, String.t()}
  def enforce_checkpoint_signing_key(signed_b64, public_key_b64)
      when is_binary(signed_b64) and is_binary(public_key_b64) do
    Native.nif_policy_enforce_checkpoint_signing_key(signed_b64, public_key_b64)
  end

  @doc """
  Enforce that a checkpoint `signature_b64` matches the verified policy's
  declared checkpoint posture. Returns `:ok` or `{:error, reason}`.
  """
  @spec enforce_checkpoint_signature(String.t(), String.t()) :: :ok | {:error, String.t()}
  def enforce_checkpoint_signature(signed_b64, signature_b64)
      when is_binary(signed_b64) and is_binary(signature_b64) do
    Native.nif_policy_enforce_checkpoint_signature(signed_b64, signature_b64)
  end

  @doc """
  Enforce that an observed VRF `suite_id` matches the policy's declared VRF
  mode. Returns `:ok` or `{:error, reason}`.
  """
  @spec enforce_vrf_suite_id(String.t(), 0..255) :: :ok | {:error, String.t()}
  def enforce_vrf_suite_id(signed_b64, suite_id)
      when is_binary(signed_b64) and is_integer(suite_id) and suite_id in 0..255 do
    Native.nif_policy_enforce_vrf_suite_id(signed_b64, suite_id)
  end

  @doc """
  Enforce that an observed `commitment_hash` (`:sha3_256` | `:sha3_512`) matches
  the policy's declaration. Returns `:ok` or `{:error, reason}`.
  """
  @spec enforce_commitment_hash(String.t(), :sha3_256 | :sha3_512) ::
          :ok | {:error, String.t()}
  def enforce_commitment_hash(signed_b64, commitment_hash)
      when is_binary(signed_b64) and commitment_hash in [:sha3_256, :sha3_512] do
    Native.nif_policy_enforce_commitment_hash(signed_b64, Atom.to_string(commitment_hash))
  end
end
