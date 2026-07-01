defmodule MetamorphicLog.Keytrans do
  @moduledoc """
  KEYTRANS combined-tree directory verification (Layer 3, experimental).

  KEYTRANS is the IETF key-transparency protocol
  (`draft-ietf-keytrans-protocol-04`): a single combined log-and-prefix tree
  that lets a relying party verify the value bound to a label — and monitor it
  for silent changes — without the operator being able to equivocate. Like
  CONIKS, verification is stateless: it recomputes everything from public inputs
  (the VRF public key, the published combined-tree root, the label, and the
  proof blob) and holds no directory state.

  These are the **verifier** functions, mirroring the browser WASM SDK's
  `keytransVerify*Suite` surface. There are three proof kinds:

    * `verify_search/6` — greatest-version search (§6): the value at a label's
      most recent version, or that the label is absent.
    * `verify_fixed_version/7` — fixed-version search (§7): the value at a
      specific version.
    * `verify_monitor/7` — monitoring (§8): that a known `(label, version)` is
      still consistently included (a downgrade is rejected).

  ## Suites

  The cipher **suite is always explicit** — there is no default. Pass one of:

    * `:kt128_sha256_p256` (`0x0001`) — the on-spec IETF standard suite:
      ECVRF-P256-SHA256-TAI labels + HMAC-SHA256 commitment.
    * `:kt128_sha256_ed25519` (`0x0002`) — the on-spec IETF standard suite:
      ECVRF-Ed25519 (truncated) labels + HMAC-SHA256 commitment.
    * `:metamorphic_hybrid_exp` (`0xF000`) — the private experimental
      hybrid-PQ suite (SHA3-512 commitment), in the §15.1 private-use range.

  The suite selects the VRF construction, commitment width, and opening length;
  it must match the suite the directory published under. The `:coniks` and
  `:keytrans` directory routes a namespace may declare are carried on the
  namespace policy (see `MetamorphicLog.Policy`).

  ## Experimental / movable posture

  Everything here is tagged `KEYTRANS_EXP_04` and **movable**: the proof wire
  format tracks the IETF draft and is deliberately *not* byte-frozen the way the
  CONIKS and checkpoint layers are. Pin the `metamorphic_log` version if you
  depend on a specific KEYTRANS wire.

  ## Arguments

  All binary arguments are **base64-encoded**:

    * `context` — the commitment domain-separation string (UTF-8), e.g.
      `"acme/keytrans-commitment/v1"`.
    * `vrf_public` — the operator's VRF public key.
    * `root` — the published combined-tree root.
    * `label` — the queried label (e.g. an account identifier).
    * `proof` — the movable KEYTRANS proof blob returned by the operator.
  """

  alias MetamorphicLog.Native

  @typedoc """
  A KEYTRANS cipher suite (§15.1).

    * `:kt128_sha256_p256` — `0x0001`
    * `:kt128_sha256_ed25519` — `0x0002`
    * `:metamorphic_hybrid_exp` — `0xF000`
  """
  @type suite :: :kt128_sha256_p256 | :kt128_sha256_ed25519 | :metamorphic_hybrid_exp

  @typedoc "A recomputed search outcome: the bound value (base64) or absence."
  @type outcome :: {:present, value_b64 :: String.t()} | :absent

  @suite_ids %{
    kt128_sha256_p256: 0x0001,
    kt128_sha256_ed25519: 0x0002,
    metamorphic_hybrid_exp: 0xF000
  }

  @doc """
  The §15.1 `suite_id` (`u16`) for a suite atom.

  ## Examples

      iex> MetamorphicLog.Keytrans.suite_id(:kt128_sha256_p256)
      1

      iex> MetamorphicLog.Keytrans.suite_id(:metamorphic_hybrid_exp)
      61_440

  """
  @spec suite_id(suite()) :: 0..0xFFFF
  def suite_id(suite) when is_map_key(@suite_ids, suite), do: Map.fetch!(@suite_ids, suite)

  @doc """
  Verify a **greatest-version search** proof (§6): the value bound to `label` at
  its most recent version under the directory committed by `root`, or that the
  label is absent.

  Returns `{:ok, {:present, value_b64}}`, `{:ok, :absent}`, or `{:error, reason}`.

  ## Example

      {:ok, {:present, value}} =
        MetamorphicLog.Keytrans.verify_search(
          :kt128_sha256_p256, context, vrf_public, root, label, proof
        )

  """
  @spec verify_search(suite(), String.t(), String.t(), String.t(), String.t(), String.t()) ::
          {:ok, outcome()} | {:error, String.t()}
  def verify_search(suite, context, vrf_public_b64, root_b64, label_b64, proof_b64)
      when is_map_key(@suite_ids, suite) and is_binary(context) and is_binary(vrf_public_b64) and
             is_binary(root_b64) and is_binary(label_b64) and is_binary(proof_b64) do
    Native.nif_keytrans_verify_search(
      suite_id(suite),
      context,
      vrf_public_b64,
      root_b64,
      label_b64,
      proof_b64
    )
  end

  @doc """
  Verify a **fixed-version search** proof (§7): the value bound to `label` at a
  specific version, or that that version is absent.

  Returns `{:ok, {:present, value_b64}}`, `{:ok, :absent}`, or `{:error, reason}`.
  """
  @spec verify_fixed_version(
          suite(),
          String.t(),
          String.t(),
          String.t(),
          String.t(),
          String.t()
        ) :: {:ok, outcome()} | {:error, String.t()}
  def verify_fixed_version(suite, context, vrf_public_b64, root_b64, label_b64, proof_b64)
      when is_map_key(@suite_ids, suite) and is_binary(context) and is_binary(vrf_public_b64) and
             is_binary(root_b64) and is_binary(label_b64) and is_binary(proof_b64) do
    Native.nif_keytrans_verify_fixed_version(
      suite_id(suite),
      context,
      vrf_public_b64,
      root_b64,
      label_b64,
      proof_b64
    )
  end

  @doc """
  Verify a **monitoring** proof (§8): that a known `(label, version)` is still
  consistently included in the directory committed by `root`. A downgrade (a
  ladder rung that no longer proves inclusion) is rejected.

  Returns `{:ok, true}` on success, or `{:error, reason}`.
  """
  @spec verify_monitor(suite(), String.t(), String.t(), String.t(), String.t(), String.t()) ::
          {:ok, boolean()} | {:error, String.t()}
  def verify_monitor(suite, context, vrf_public_b64, root_b64, label_b64, proof_b64)
      when is_map_key(@suite_ids, suite) and is_binary(context) and is_binary(vrf_public_b64) and
             is_binary(root_b64) and is_binary(label_b64) and is_binary(proof_b64) do
    Native.nif_keytrans_verify_monitor(
      suite_id(suite),
      context,
      vrf_public_b64,
      root_b64,
      label_b64,
      proof_b64
    )
  end
end
