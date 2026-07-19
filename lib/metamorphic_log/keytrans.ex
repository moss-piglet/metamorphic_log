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

  # ─── Directory construction (operator / prover side) ────────────────────────

  @typedoc """
  An opaque, stateful KEYTRANS directory resource owned by the runtime.

  Held as a reference to a Rust-side `RwLock<KeytransDirectory>`: reads
  (`combined_root/1`, `prove_search/2`, `directory_vrf_public/1`) run
  concurrently, appends (`update/5`) are serialized. It maintains the single
  logical prefix tree and the chronological combined tree — built once with
  `directory_open/3` and grown incrementally with `update/5`, rather than
  rebuilt per request. Not serializable; do not persist it. Persist the VRF
  secret (see `generate_vrf_key/1`) and replay versions to rebuild.

  **Experimental**: the KEYTRANS wire is movable and not byte-frozen. `#45`
  serving launches CONIKS-only; this surface backs the follow-up path.
  """
  @opaque directory :: reference()

  @doc """
  Generate a fresh VRF keypair for `suite`.

  Returns `{:ok, {secret_b64, public_b64}}`. The `secret_b64` is per-namespace
  **operator infrastructure** — persist it securely and pass it to
  `directory_open/3`; it is not user key material and not a signing key. The
  `public_b64` is published so relying parties can verify proofs.
  """
  @spec generate_vrf_key(suite()) :: {:ok, {String.t(), String.t()}} | {:error, String.t()}
  def generate_vrf_key(suite) when is_map_key(@suite_ids, suite) do
    Native.nif_keytrans_generate_vrf_key(suite_id(suite))
  end

  @doc """
  Open a per-namespace directory on `suite` from an existing VRF secret key,
  committing values under `context`, returning an opaque, empty `t:directory/0`
  resource.

  Replay the namespace's versions into it with `update/5` to reconstruct the
  current directory. Returns `{:ok, directory}` or `{:error, reason}` (an unknown
  suite or a structurally invalid secret key).
  """
  @spec directory_open(suite(), context :: String.t(), vrf_secret_b64 :: String.t()) ::
          {:ok, directory()} | {:error, String.t()}
  def directory_open(suite, context, vrf_secret_b64)
      when is_map_key(@suite_ids, suite) and is_binary(context) and is_binary(vrf_secret_b64) do
    Native.nif_keytrans_directory_open(suite_id(suite), context, vrf_secret_b64)
  end

  @doc """
  Append a new version of `label` with `value`, published at `timestamp`
  (milliseconds since the Unix epoch) and blinded by `opening` — the suite's
  `Nc`-byte commitment opening, which the operator supplies from a CSPRNG.
  Serialized against other appends.

  Returns `{:ok, version}` with the new zero-based version number, or
  `{:error, reason}` (a wrong opening length, VRF failure, or oversized
  commitment inputs).
  """
  @spec update(
          directory(),
          label_b64 :: String.t(),
          value_b64 :: String.t(),
          timestamp :: non_neg_integer(),
          opening_b64 :: String.t()
        ) :: {:ok, non_neg_integer()} | {:error, String.t()}
  def update(directory, label_b64, value_b64, timestamp, opening_b64)
      when is_reference(directory) and is_binary(label_b64) and is_binary(value_b64) and
             is_integer(timestamp) and timestamp >= 0 and is_binary(opening_b64) do
    Native.nif_keytrans_directory_update(directory, label_b64, value_b64, timestamp, opening_b64)
  end

  @doc """
  The current combined-tree root (the published directory root), base64-encoded.

  Returns `{:ok, root_b64}` or `{:error, reason}` (an empty directory has no
  root).
  """
  @spec combined_root(directory()) :: {:ok, String.t()} | {:error, String.t()}
  def combined_root(directory) when is_reference(directory) do
    Native.nif_keytrans_directory_combined_root(directory)
  end

  @doc """
  Produce a **greatest-version search** proof for `label` against the current log
  head.

  Returns `{:ok, {:present, value_b64, proof_b64}}` when the label has a value,
  `{:ok, {:absent, proof_b64}}` when it does not, or `{:error, reason}` (an empty
  directory or VRF failure). The returned `proof_b64` verifies via
  `verify_search/6` against the published `directory_vrf_public/1` key and
  `combined_root/1`.
  """
  @spec prove_search(directory(), label_b64 :: String.t()) ::
          {:ok, {:present, String.t(), String.t()}}
          | {:ok, {:absent, String.t()}}
          | {:error, String.t()}
  def prove_search(directory, label_b64)
      when is_reference(directory) and is_binary(label_b64) do
    Native.nif_keytrans_directory_prove_search(directory, label_b64)
  end

  @doc """
  The VRF public key (base64) relying parties use to verify this directory's
  proofs. Returns `{:ok, vrf_public_b64}`.
  """
  @spec directory_vrf_public(directory()) :: {:ok, String.t()} | {:error, String.t()}
  def directory_vrf_public(directory) when is_reference(directory) do
    Native.nif_keytrans_directory_vrf_public(directory)
  end
end
