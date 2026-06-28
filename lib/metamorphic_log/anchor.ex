defmodule MetamorphicLog.Anchor do
  @moduledoc """
  Backend-agnostic **anchoring / attestation** (Slice 8).

  A transparency log's anti-equivocation guarantee is only as strong as a
  relying party's ability to detect a *split view* — an operator showing one
  checkpoint to Alice and a different, inconsistent one to Bob. Independent
  witnesses (`MetamorphicLog.Note`) are one defence; **anchoring** is the other:
  periodically committing a checkpoint's signed tree head to an external,
  hard-to-equivocate medium (a blockchain transaction, an [RFC 3161] notary
  receipt, object-lock / WORM storage, or another transparency log) so the
  operator cannot later present a tree that disagrees with what was anchored
  without that contradiction being publicly visible.

  This module surfaces the engine's contribution to anchoring — the **format**
  and the **verification** — and is deliberately *backend-agnostic and I/O-free*.
  There is **no** network client, chain RPC, or notary integration here, and no
  anchor *cadence / fee / confirmation-depth* policy: those belong to the
  operator (the paid mosskeys app). What lives here is:

    * `record_canonical_bytes/6` / `parse_record/1` — the canonical, byte-locked
      attestation record binding a checkpoint head (`origin`, `size`,
      `root_hash`) to an opaque `locator` and an agnostic `medium` tag.
    * `anchor_commitment/1` — the fixed-size, medium-independent commitment an
      operator publishes to (and re-fetches from) the medium.
    * `verify_anchored/4` — the third-party audit that an attestation binds a
      checkpoint and that successive anchored heads are append-only consistent,
      trusting neither the operator nor the medium.
    * `verify_commitment/2` — the medium-side counterpart: check bytes fetched
      from the medium equal the recomputed commitment.

  ## I/O stays on the BEAM side

  The Rust core's `CommitmentSink` trait (and its logic-only `*_via` bridges) is
  intentionally **not** wrapped: a sink with an associated error type and a real
  backend (chain/notary/object store) is idiomatically BEAM code. Your operator
  publishes/fetches the commitment bytes itself, then uses `anchor_commitment/1`
  + `verify_commitment/2` to check them.

  ## Honest framing (no zero-knowledge)

  This is **plain anchoring**: publish a checkpoint-head commitment and prove
  consistency between successive anchored heads. It involves **zero**
  zero-knowledge machinery; the optional ZK-anchoring enhancement is a separate
  effort and is not coupled to this format.

  Binary values are **base64-encoded** (standard padded alphabet), byte-identical
  to the native Rust core and the browser WASM SDK.

  [RFC 3161]: https://www.rfc-editor.org/rfc/rfc3161
  """

  alias MetamorphicLog.Native

  @typedoc """
  A parsed anchor record:

    * `:origin` — the bound checkpoint origin (log identity)
    * `:size` — the bound checkpoint tree size
    * `:root` — base64 RFC 6962 root hash at `size` (32 bytes)
    * `:commitment_alg` — the safe-menu commitment algorithm (`"sha3_512"`)
    * `:medium` — the medium identifier (e.g. `"ethereum/mainnet"`)
    * `:locator` — base64 opaque external-commitment locator
  """
  @type anchor_record :: %{
          origin: String.t(),
          size: non_neg_integer(),
          root: String.t(),
          commitment_alg: String.t(),
          medium: String.t(),
          locator: String.t()
        }

  @doc """
  Build the canonical bytes of an anchor attestation record from an explicit
  checkpoint head.

  `medium` is a printable-ASCII identifier (no whitespace/control bytes, `/`
  allowed for hierarchy, e.g. `"ethereum/mainnet"`); `locator_b64` is the opaque
  external-commitment handle (tx id, block height, receipt, object key);
  `commitment_alg` is a safe-menu tag (`"sha3_512"`, the v0.1 default and only
  entry). Returns `{:ok, record_b64}` or `{:error, reason}`.
  """
  @spec record_canonical_bytes(
          origin :: String.t(),
          size :: non_neg_integer(),
          root_b64 :: String.t(),
          medium :: String.t(),
          locator_b64 :: String.t(),
          commitment_alg :: String.t()
        ) :: {:ok, String.t()} | {:error, String.t()}
  def record_canonical_bytes(
        origin,
        size,
        root_b64,
        medium,
        locator_b64,
        commitment_alg \\ "sha3_512"
      )
      when is_binary(origin) and is_integer(size) and size >= 0 and is_binary(root_b64) and
             is_binary(medium) and is_binary(locator_b64) and is_binary(commitment_alg) do
    Native.nif_anchor_record_canonical_bytes(
      origin,
      size,
      root_b64,
      commitment_alg,
      medium,
      locator_b64
    )
  end

  @doc """
  Parse a canonical anchor record into a `t:anchor_record/0` map. Validates the layout,
  format version, algorithm tag, medium grammar, and non-empty origin/locator.
  Returns `{:ok, record}` or `{:error, reason}`.
  """
  @spec parse_record(record_b64 :: String.t()) :: {:ok, anchor_record()} | {:error, String.t()}
  def parse_record(record_b64) when is_binary(record_b64) do
    case Native.nif_anchor_record_parse(record_b64) do
      {:ok, {origin, size, root, commitment_alg, medium, locator}} ->
        {:ok,
         %{
           origin: origin,
           size: size,
           root: root,
           commitment_alg: commitment_alg,
           medium: medium,
           locator: locator
         }}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  The fixed-size commitment over the record's checkpoint head — the value an
  operator publishes to (and re-fetches from) the external medium.

  Medium- and locator-independent: the same head yields the same commitment
  regardless of where it is anchored. Returns `{:ok, commitment_b64}` or
  `{:error, reason}`. Runs on a dirty CPU scheduler.
  """
  @spec anchor_commitment(record_b64 :: String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def anchor_commitment(record_b64) when is_binary(record_b64) do
    Native.nif_anchor_commitment(record_b64)
  end

  @doc """
  The RFC 6962 Merkle leaf hash of the record's canonical bytes, so an operator
  may also log its attestations as Layer-0 leaves. Returns `{:ok, hash_b64}` or
  `{:error, reason}`. Dirty CPU.
  """
  @spec rfc6962_leaf_hash(record_b64 :: String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def rfc6962_leaf_hash(record_b64) when is_binary(record_b64) do
    Native.nif_anchor_record_rfc6962_leaf_hash(record_b64)
  end

  @doc """
  Verify an anchored checkpoint.

  Checks that `record_b64` binds the checkpoint carried by `note_text` (verified
  against the trusted `vkeys`), and — when a previous anchored checkpoint is
  supplied — that the newer checkpoint is an append-only extension of it.

  This is the log-side audit of *"the operator never equivocated between anchored
  heads"*: it trusts neither the operator nor the medium. Pair it with
  `verify_commitment/2` (the medium-side check) for the full guarantee. Runs on a
  dirty CPU scheduler.

  ## Options

    * `:prev_note` — a previously-anchored checkpoint signed note. When given,
      consistency from it to `note_text` is verified.
    * `:consistency_proof` — a list of base64 RFC 9162 consistency-proof hashes
      from `:prev_note` to `note_text` (each 32 bytes). Required (and only used)
      when `:prev_note` is set.

  With no `:prev_note`, only the attestation-binds-checkpoint check runs.

  Returns `:ok` on success or `{:error, reason}` (a failed binding/consistency
  check or malformed input).

  ## Examples

      # binding-only
      :ok = MetamorphicLog.Anchor.verify_anchored(note, [vkey], record)

      # binding + consistency from a previous anchored head
      :ok =
        MetamorphicLog.Anchor.verify_anchored(newer_note, [vkey], record,
          prev_note: older_note,
          consistency_proof: proof_b64
        )

  """
  @spec verify_anchored(
          note_text :: String.t(),
          vkeys :: [String.t()],
          record_b64 :: String.t(),
          opts :: keyword()
        ) :: :ok | {:error, String.t()}
  def verify_anchored(note_text, vkeys, record_b64, opts \\ [])
      when is_binary(note_text) and is_list(vkeys) and is_binary(record_b64) and is_list(opts) do
    prev_note = Keyword.get(opts, :prev_note)
    proof = Keyword.get(opts, :consistency_proof, [])
    Native.nif_verify_anchored(note_text, vkeys, record_b64, prev_note, proof)
  end

  @doc """
  Medium-side check: the bytes `fetched_commitment_b64` retrieved from the
  external medium equal the commitment recomputed from `record_b64`'s checkpoint
  head.

  On `:ok` the medium genuinely attests to this checkpoint head. This is the
  counterpart to `verify_anchored/4`: together they prove *the head was anchored*
  and *the operator never equivocated between anchored heads*. The fetch itself
  is your operator's job (this library performs no I/O).

  Returns `:ok`, `{:error, :commitment_mismatch}`, or `{:error, reason}` if the
  record is malformed.
  """
  @spec verify_commitment(record_b64 :: String.t(), fetched_commitment_b64 :: String.t()) ::
          :ok | {:error, :commitment_mismatch | String.t()}
  def verify_commitment(record_b64, fetched_commitment_b64)
      when is_binary(record_b64) and is_binary(fetched_commitment_b64) do
    case anchor_commitment(record_b64) do
      {:ok, ^fetched_commitment_b64} -> :ok
      {:ok, _other} -> {:error, :commitment_mismatch}
      {:error, _} = error -> error
    end
  end
end
