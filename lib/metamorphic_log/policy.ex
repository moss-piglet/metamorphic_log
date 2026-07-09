defmodule MetamorphicLog.Policy do
  @moduledoc """
  Signed **namespace policy** verification and declared-vs-observed enforcement.

  A namespace policy is a signed, in-log, versioned record declaring the
  cryptographic posture a namespace operates under: checkpoint signature suite
  and security level, the CONIKS commitment hash, the VRF mode, and the
  directory route (CONIKS vs the experimental IETF KEYTRANS backend and its
  cipher suite). Because the policy is itself a log leaf, the posture is
  auditable and tamper-evident.

  `verify/1` checks the policy's self-signature and returns the declared
  posture. The `enforce_*` functions then assert that an **observed** artifact
  (a checkpoint signing key, a checkpoint signature, a VRF suite id, a
  commitment hash, or a directory backend id) matches what the verified policy
  **declares** — the "declared == observed" invariant that stops an operator
  from silently downgrading.

  The signed policy envelope is **base64-encoded**.
  """

  alias MetamorphicLog.Native

  @typedoc """
  A verified namespace policy.

  * `:security_level` — `:cat3` | `:cat5`
  * `:checkpoint_suite` — `:hybrid` | `:hybrid_matched` | `:pure_cnsa2`
  * `:commitment_hash` — `:sha3_256` | `:sha3_512`
  * `:vrf_mode` — `:classical` | `:hybrid_output` | `:pure_pq_experimental`
  * `:directory_mode` — `:coniks` | `:keytrans` (the Layer-3 directory route)
  * `:keytrans_suite` — `:metamorphic_hybrid_exp` | `:kt128_sha256_p256` |
    `:kt128_sha256_ed25519` (only meaningful when `:directory_mode` is
    `:keytrans`; the default suite otherwise)
  * `:policy_hash`, `:rfc6962_leaf_hash` — base64-encoded
  """
  @type t :: %__MODULE__{
          namespace: String.t(),
          policy_schema_version: non_neg_integer(),
          security_level: :cat3 | :cat5,
          checkpoint_suite: :hybrid | :hybrid_matched | :pure_cnsa2,
          commitment_hash: :sha3_256 | :sha3_512,
          vrf_mode: :classical | :hybrid_output | :pure_pq_experimental,
          directory_mode: :coniks | :keytrans,
          keytrans_suite: :metamorphic_hybrid_exp | :kt128_sha256_p256 | :kt128_sha256_ed25519,
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
    :directory_mode,
    :keytrans_suite,
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
      {:ok,
       {{namespace, schema_version, level, suite, commit_hash}, {vrf, eff, created, ph, lh},
        {dir_mode, kt_suite}}} ->
        {:ok,
         %__MODULE__{
           namespace: namespace,
           policy_schema_version: schema_version,
           security_level: security_level(level),
           checkpoint_suite: checkpoint_suite(suite),
           commitment_hash: commitment_hash(commit_hash),
           vrf_mode: vrf_mode(vrf),
           directory_mode: directory_mode(dir_mode),
           keytrans_suite: keytrans_suite(kt_suite),
           effective_from: eff,
           created_at: created,
           policy_hash: ph,
           rfc6962_leaf_hash: lh
         }}

      {:error, _reason} = error ->
        error
    end
  end

  @doc """
  Sign a namespace policy and return its base64-encoded signed envelope, the
  producer counterpart to `verify/1`.

  `params` is a keyword list or map declaring the posture to attest. The enum
  fields take the **same atoms `verify/1` returns**, so a verified policy can be
  re-signed by feeding its struct fields straight back in:

  * `:namespace` (required) — the namespace identity string
  * `:policy_schema_version` (required) — non-negative integer
  * `:security_level` (required) — `:cat3` | `:cat5`
  * `:checkpoint_suite` (required) — `:hybrid` | `:hybrid_matched` | `:pure_cnsa2`
  * `:commitment_hash` (required) — `:sha3_256` | `:sha3_512`
  * `:vrf_mode` (required) — `:classical` | `:hybrid_output` | `:pure_pq_experimental`
  * `:directory_mode` (required) — `:coniks` | `:keytrans`
  * `:keytrans_suite` (required only when `:directory_mode` is `:keytrans`) —
    `:metamorphic_hybrid_exp` | `:kt128_sha256_p256` | `:kt128_sha256_ed25519`;
    ignored for the CONIKS route (defaults to `:metamorphic_hybrid_exp`)
  * `:effective_from` (required) — non-negative integer timestamp
  * `:created_at` (required) — non-negative integer timestamp
  * `:prev_policy_hash` (optional) — base64 of the previous policy's 64-byte
    hash to chain revisions, or `nil` for the first policy

  `secret_key_b64` is the base64 metamorphic-crypto composite secret key. ML-DSA
  signing is hedged, so the envelope bytes are not reproducible, but the result
  verifies deterministically via `verify/1`.

  Returns `{:ok, signed_b64}` or `{:error, reason}` (unknown enum value,
  malformed namespace, a `prev_policy_hash` that is not 64 bytes, or a signing
  failure).

  ## Example

      {:ok, signed} =
        MetamorphicLog.Policy.sign(
          [
            namespace: "metamorphic.app/log",
            policy_schema_version: 1,
            security_level: :cat3,
            checkpoint_suite: :hybrid,
            commitment_hash: :sha3_256,
            vrf_mode: :classical,
            directory_mode: :coniks,
            effective_from: 0,
            created_at: 0
          ],
          secret_key_b64
        )

  """
  @keytrans_suites [:metamorphic_hybrid_exp, :kt128_sha256_p256, :kt128_sha256_ed25519]

  @spec sign(
          params :: Enumerable.t(),
          secret_key_b64 :: String.t()
        ) :: {:ok, String.t()} | {:error, String.t()}
  def sign(params, secret_key_b64) when is_binary(secret_key_b64) do
    p = Map.new(params)

    with {:ok, namespace} <- fetch_binary(p, :namespace),
         {:ok, schema_version} <- fetch_non_neg_int(p, :policy_schema_version),
         {:ok, level} <- fetch_enum(p, :security_level, [:cat3, :cat5]),
         {:ok, suite} <-
           fetch_enum(p, :checkpoint_suite, [:hybrid, :hybrid_matched, :pure_cnsa2]),
         {:ok, commit} <- fetch_enum(p, :commitment_hash, [:sha3_256, :sha3_512]),
         {:ok, vrf} <-
           fetch_enum(p, :vrf_mode, [:classical, :hybrid_output, :pure_pq_experimental]),
         {:ok, dir} <- fetch_enum(p, :directory_mode, [:coniks, :keytrans]),
         {:ok, kt} <-
           fetch_enum(p, :keytrans_suite, @keytrans_suites, :metamorphic_hybrid_exp),
         {:ok, effective_from} <- fetch_non_neg_int(p, :effective_from),
         {:ok, created_at} <- fetch_non_neg_int(p, :created_at) do
      Native.nif_signed_policy_sign(
        namespace,
        schema_version,
        Atom.to_string(level),
        Atom.to_string(suite),
        Atom.to_string(commit),
        Atom.to_string(vrf),
        Atom.to_string(dir),
        Atom.to_string(kt),
        effective_from,
        created_at,
        Map.get(p, :prev_policy_hash),
        secret_key_b64
      )
    end
  end

  defp fetch_binary(p, key) do
    case Map.fetch(p, key) do
      {:ok, value} when is_binary(value) -> {:ok, value}
      {:ok, _} -> {:error, "#{key} must be a string"}
      :error -> {:error, "missing required policy field: #{key}"}
    end
  end

  defp fetch_non_neg_int(p, key) do
    case Map.fetch(p, key) do
      {:ok, value} when is_integer(value) and value >= 0 -> {:ok, value}
      {:ok, _} -> {:error, "#{key} must be a non-negative integer"}
      :error -> {:error, "missing required policy field: #{key}"}
    end
  end

  defp fetch_enum(p, key, allowed, default \\ :__required__) do
    case Map.get(p, key, default) do
      :__required__ ->
        {:error, "missing required policy field: #{key}"}

      value ->
        if value in allowed do
          {:ok, value}
        else
          {:error, "invalid #{key}: #{inspect(value)} (allowed: #{inspect(allowed)})"}
        end
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

  defp directory_mode("coniks"), do: :coniks
  defp directory_mode("keytrans"), do: :keytrans

  defp keytrans_suite("metamorphic_hybrid_exp"), do: :metamorphic_hybrid_exp
  defp keytrans_suite("kt128_sha256_p256"), do: :kt128_sha256_p256
  defp keytrans_suite("kt128_sha256_ed25519"), do: :kt128_sha256_ed25519

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

  @typedoc """
  A directory backend identifier (§3.3 `DirectoryBackendId`, a `u16`).

  Pass either a well-known atom or the raw id:

  * `:coniks` — the shipped, frozen CONIKS prefix-tree backend (`0x0001`)
  * `:keytrans` — the experimental IETF KEYTRANS combined-tree backend
    (`0xF004`, `KEYTRANS_EXP_V04`; movable — the id tracks the draft)
  """
  @type directory_backend :: :coniks | :keytrans | 0..0xFFFF

  @doc """
  Enforce that an **observed** directory backend matches the one the verified
  policy declares (from its `:directory_mode` / `:keytrans_suite` axis).

  A CONIKS-route policy must be served by the CONIKS backend; a KEYTRANS-route
  policy by the KEYTRANS combined-tree backend. Any disagreement — including a
  route that declares a reserved/not-built suite — is a hard rejection.

  `observed` is a `directory_backend/0`: `:coniks`, `:keytrans`, or a raw
  `u16`. Returns `:ok` or `{:error, reason}`.

  ## Example

      :ok = MetamorphicLog.Policy.enforce_directory_backend(signed_b64, :coniks)

  """
  @spec enforce_directory_backend(String.t(), directory_backend()) ::
          :ok | {:error, String.t()}
  def enforce_directory_backend(signed_b64, observed)
      when is_binary(signed_b64) do
    Native.nif_policy_enforce_directory_backend(signed_b64, backend_id(observed))
  end

  @coniks_backend_id 0x0001
  @keytrans_exp_backend_id 0xF004

  defp backend_id(:coniks), do: @coniks_backend_id
  defp backend_id(:keytrans), do: @keytrans_exp_backend_id
  defp backend_id(id) when is_integer(id) and id in 0..0xFFFF, do: id
end
