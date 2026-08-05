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

  # ─── Directory construction (operator / prover side) ────────────────────────

  @typedoc """
  An opaque, stateful CONIKS directory resource owned by the runtime.

  Held as a reference to a Rust-side `RwLock<ConiksDirectory>`: reads
  (`root/1`, `lookup/2`, `vrf_public/1`) run concurrently, appends (`insert/3`)
  are serialized. It is derived from a namespace's append-only log — built once
  with `directory_open/2` and updated incrementally with `insert/3`, rather than
  rebuilt per request. Not serializable; do not persist it. Persist the VRF
  secret (see `generate_vrf_key/0`) and replay entries to rebuild.
  """
  @opaque directory :: reference()

  @doc """
  Generate a fresh classical VRF keypair (RFC 9381 ECVRF over edwards25519,
  suite `0x03`) for a namespace directory.

  Returns `{:ok, {secret_b64, public_b64}}`. The `secret_b64` is per-namespace
  **operator infrastructure** — persist it securely and pass it to
  `directory_open/2`; it is not user key material and not a signing key. The
  `public_b64` is published so relying parties can verify lookups.
  """
  @spec generate_vrf_key() :: {:ok, {String.t(), String.t()}} | {:error, String.t()}
  def generate_vrf_key, do: Native.nif_coniks_generate_vrf_key()

  @doc """
  Open a per-namespace directory from an existing VRF secret key, returning an
  opaque, empty `t:directory/0` resource.

  Replay the namespace's entries into it with `insert/3` to reconstruct the
  current directory. Returns `{:ok, directory}` or `{:error, reason}` (a
  malformed `namespace` or structurally invalid secret key).
  """
  @spec directory_open(namespace :: String.t(), vrf_secret_b64 :: String.t()) ::
          {:ok, directory()} | {:error, String.t()}
  def directory_open(namespace, vrf_secret_b64)
      when is_binary(namespace) and is_binary(vrf_secret_b64) do
    Native.nif_coniks_directory_open(namespace, vrf_secret_b64)
  end

  @doc """
  Insert (or replace) `identity`'s `value` in the directory, committing to it at
  the identity's VRF-derived index. Serialized against other appends.

  Returns `:ok` or `{:error, reason}`.
  """
  @spec insert(directory(), identity_b64 :: String.t(), value_b64 :: String.t()) ::
          :ok | {:error, String.t()}
  def insert(directory, identity_b64, value_b64)
      when is_reference(directory) and is_binary(identity_b64) and is_binary(value_b64) do
    Native.nif_coniks_directory_insert(directory, identity_b64, value_b64)
  end

  @doc """
  The current directory root: the 64-byte SHA3-512 prefix-tree root over all
  commitments, base64-encoded. Returns `{:ok, root_b64}`.
  """
  @spec root(directory()) :: {:ok, String.t()} | {:error, String.t()}
  def root(directory) when is_reference(directory) do
    Native.nif_coniks_directory_root(directory)
  end

  @doc """
  Look up `identity`, producing a presence or absence proof against the current
  root.

  Returns `{:ok, {:present, value_b64, proof_b64}}` when the identity is bound,
  `{:ok, {:absent, proof_b64}}` when it is not, or `{:error, reason}`. The
  returned `proof_b64` verifies via `verify_lookup/5` (presence) or
  `verify_absence/5` (absence) against the published `vrf_public/1` key and
  `root/1`.
  """
  @spec lookup(directory(), identity_b64 :: String.t()) ::
          {:ok, {:present, String.t(), String.t()}}
          | {:ok, {:absent, String.t()}}
          | {:error, String.t()}
  def lookup(directory, identity_b64)
      when is_reference(directory) and is_binary(identity_b64) do
    Native.nif_coniks_directory_lookup(directory, identity_b64)
  end

  @doc """
  The VRF public key (base64) relying parties use to verify this directory's
  proofs. Returns `{:ok, vrf_public_b64}`.
  """
  @spec vrf_public(directory()) :: {:ok, String.t()} | {:error, String.t()}
  def vrf_public(directory) when is_reference(directory) do
    Native.nif_coniks_directory_vrf_public(directory)
  end

  # ─── POPRF (RFC 9497) oblivious index derivation ───────────────────────────
  #
  # The POPRF-backed directory personality: same tree, same proofs, but the
  # query-time cleartext-label exposure is gone — the server only ever sees a
  # blinded element (an online, rate-limited evaluation) or an already-derived
  # 32-byte index. The deployment evaluation key is derived from a managed
  # secret via RFC 9497 §3.2.1 (`derive_poprf_key_pair/2`); the per-namespace
  # binding is the public `info` string threaded through open/evaluate.
  #
  # The client side (blind / unblind / DLEQ verify) lives in the
  # `metamorphic_crypto` primitive surface (native and WASM), pinned to the RFC
  # 9497 test vectors.

  @doc """
  Derive the deployment POPRF keypair from a 32-byte seed and a public key-info
  string (RFC 9497 §3.2.1 `DeriveKeyPair`).

  Returns `{:ok, {secret_b64, public_b64}}`. The `secret_b64` is deployment
  **operator infrastructure** — persist it securely and pass it to
  `directory_open_poprf/3`; it is not user key material and not a signing key.
  The `public_b64` is published so clients can blind under it and verify DLEQ
  proofs.
  """
  @spec derive_poprf_key_pair(seed_b64 :: String.t(), key_info_b64 :: String.t()) ::
          {:ok, {String.t(), String.t()}} | {:error, String.t()}
  def derive_poprf_key_pair(seed_b64, key_info_b64)
      when is_binary(seed_b64) and is_binary(key_info_b64) do
    Native.nif_poprf_derive_key_pair(seed_b64, key_info_b64)
  end

  @doc """
  Open a per-namespace **POPRF-backed** directory from the deployment POPRF
  secret key, returning an opaque, empty `t:directory/0` resource.

  `info_b64` is the base64 public POPRF metadata binding this namespace's
  evaluations (e.g. `"mosskeys/directory/v1:<namespace_id>"`); it is threaded
  through both construction and serving, and clients must use the identical
  `info` to recover the same index. Replay the namespace's entries with
  `insert/3` to reconstruct the current directory (insert-time index derivation
  is the non-oblivious RFC 9497 `Evaluate`, matching what clients derive
  obliviously). Returns `{:ok, directory}` or `{:error, reason}`.
  """
  @spec directory_open_poprf(
          namespace :: String.t(),
          info_b64 :: String.t(),
          poprf_secret_b64 :: String.t()
        ) :: {:ok, directory()} | {:error, String.t()}
  def directory_open_poprf(namespace, info_b64, poprf_secret_b64)
      when is_binary(namespace) and is_binary(info_b64) and is_binary(poprf_secret_b64) do
    Native.nif_coniks_directory_open_poprf(namespace, info_b64, poprf_secret_b64)
  end

  @doc """
  Look up a 32-byte derived tree `index`, producing an **index-bound** presence
  or absence proof against the current root — the POPRF serving path. No
  identity, no cleartext label: the caller derived the index obliviously and
  verifies with `verify_indexed_lookup/6` / `verify_indexed_absence/6`.

  Returns `{:ok, {:present, value_b64, proof_b64}}` when a leaf is bound at the
  index, `{:ok, {:absent, proof_b64}}` when it holds the empty leaf, or
  `{:error, reason}`.
  """
  @spec lookup_by_index(directory(), index_b64 :: String.t()) ::
          {:ok, {:present, String.t(), String.t()}}
          | {:ok, {:absent, String.t()}}
          | {:error, String.t()}
  def lookup_by_index(directory, index_b64)
      when is_reference(directory) and is_binary(index_b64) do
    Native.nif_coniks_directory_lookup_by_index(directory, index_b64)
  end

  @doc """
  The server-side oblivious evaluation (RFC 9497 `BlindEvaluate`): evaluate a
  client's blinded element under this directory's POPRF key.

  Returns `{:ok, {evaluated_element_b64, dleq_proof_b64}}` or `{:error,
  reason}`. The directory learns nothing about the identity behind the blinded
  element. **POPRF-backed directories only.**
  """
  @spec blind_evaluate(directory(), blinded_element_b64 :: String.t()) ::
          {:ok, {String.t(), String.t()}} | {:error, String.t()}
  def blind_evaluate(directory, blinded_element_b64)
      when is_reference(directory) and is_binary(blinded_element_b64) do
    Native.nif_coniks_directory_blind_evaluate(directory, blinded_element_b64)
  end

  @doc """
  The POPRF public key (base64) clients blind under, for a POPRF-backed
  directory. Returns `{:ok, poprf_public_b64}` or `{:error, reason}`.
  """
  @spec poprf_public(directory()) :: {:ok, String.t()} | {:error, String.t()}
  def poprf_public(directory) when is_reference(directory) do
    Native.nif_coniks_directory_poprf_public(directory)
  end

  @doc """
  The public POPRF `info` metadata (base64) binding this directory's
  evaluations, for a POPRF-backed directory. Returns `{:ok, info_b64}` or
  `{:error, reason}`.
  """
  @spec poprf_info(directory()) :: {:ok, String.t()} | {:error, String.t()}
  def poprf_info(directory) when is_reference(directory) do
    Native.nif_coniks_directory_poprf_info(directory)
  end

  @doc """
  This directory's index-derivation suite identifier — an RFC 9381 octet for a
  VRF directory (`0x03` classical ECVRF), `0x80` for a POPRF one — bound into
  every leaf hash. Clients need it to verify index-bound proofs. Returns
  `{:ok, suite_id}`.
  """
  @spec suite_id(directory()) :: {:ok, non_neg_integer()} | {:error, String.t()}
  def suite_id(directory) when is_reference(directory) do
    Native.nif_coniks_directory_suite_id(directory)
  end

  @doc """
  Verify an **index-bound presence** proof (the POPRF oblivious-lookup path):
  the caller's self-derived 32-byte `index` plus the canonical
  `IndexedLookupProof` bytes against `root`. No identity or scheme key is
  needed — the index itself is the caller's evidence.

  Returns `{:ok, value_b64}` with the bound value on success, or `{:error,
  reason}`.
  """
  @spec verify_indexed_lookup(
          namespace :: String.t(),
          suite_id :: non_neg_integer(),
          root_b64 :: String.t(),
          index_b64 :: String.t(),
          proof_b64 :: String.t()
        ) :: {:ok, String.t()} | {:error, String.t()}
  def verify_indexed_lookup(namespace, suite_id, root_b64, index_b64, proof_b64)
      when is_binary(namespace) and is_integer(suite_id) and is_binary(root_b64) and
             is_binary(index_b64) and is_binary(proof_b64) do
    Native.nif_coniks_verify_indexed_lookup(
      namespace,
      suite_id,
      root_b64,
      index_b64,
      proof_b64
    )
  end

  @doc """
  Verify an **index-bound absence** proof: the index provably holds the empty
  leaf under `root`. Returns `:ok` or `{:error, reason}`.
  """
  @spec verify_indexed_absence(
          namespace :: String.t(),
          suite_id :: non_neg_integer(),
          root_b64 :: String.t(),
          index_b64 :: String.t(),
          proof_b64 :: String.t()
        ) :: :ok | {:error, String.t()}
  def verify_indexed_absence(namespace, suite_id, root_b64, index_b64, proof_b64)
      when is_binary(namespace) and is_integer(suite_id) and is_binary(root_b64) and
             is_binary(index_b64) and is_binary(proof_b64) do
    Native.nif_coniks_verify_indexed_absence(
      namespace,
      suite_id,
      root_b64,
      index_b64,
      proof_b64
    )
  end
end
