defmodule MetamorphicLog.Ingest do
  @moduledoc """
  Deterministic ingestion / scale primitives for an Elixir operator pipeline.

  These are the building blocks for *operating* a log (not just verifying one):
  content **dedup keys**, tile **flush geometry**, and Merkle **recomputation**
  over tile bytes. They are pure and side-effect-free — sequencing state and
  tile storage I/O stay on the BEAM side, which is the idiomatic split (NIFs do
  CPU-bound math; the BEAM owns state and I/O).

  ### Sequencing & tile I/O live in Elixir

  The Rust core's `Sequencer` and `TileReader` are intentionally *not* wrapped:
  a sequencer is a per-namespace monotonic counter best kept as BEAM state
  (e.g. an `Agent`/`GenServer` or a DB column), and tile reads are storage I/O.
  Instead, your pipeline reads tile bytes from wherever they live and feeds them
  to `tile_hashes/4`, `parent_hash/1`, and `recompute_root/1` — the dirty-CPU
  hashing primitives — to reproduce a root from tiles.

  Binary values are **base64-encoded**; tile paths are returned as
  `tile/<level>/<index>[.p/<width>]` strings.
  """

  alias MetamorphicLog.Native

  @doc """
  Content dedup key for a `payload` under `namespace`, base64-encoded (64 bytes).

  Domain-separated as `SHA3-512_with_context("metamorphic-log/ingest-dedup-content/v1", lp(ns) || lp(payload))`.

  ## Example

      {:ok, key} = MetamorphicLog.Ingest.dedup_key_from_record("acme", payload_b64)

  """
  @spec dedup_key_from_record(namespace :: String.t(), payload_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def dedup_key_from_record(namespace, payload_b64)
      when is_binary(namespace) and is_binary(payload_b64) do
    Native.nif_dedup_key_from_record(namespace, payload_b64)
  end

  @doc """
  Token dedup key for an idempotency `token` under `namespace`, base64-encoded.

  Uses the `metamorphic-log/ingest-dedup-token/v1` context.
  """
  @spec dedup_key_from_token(namespace :: String.t(), token_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def dedup_key_from_token(namespace, token_b64)
      when is_binary(namespace) and is_binary(token_b64) do
    Native.nif_dedup_key_from_token(namespace, token_b64)
  end

  @doc """
  Tile paths that must be (re)written when the tree grows from `old_size` to
  `new_size` leaves. Returns `{:ok, [path]}` or `{:error, reason}`.
  """
  @spec tiles_to_flush(non_neg_integer(), non_neg_integer()) ::
          {:ok, [String.t()]} | {:error, String.t()}
  def tiles_to_flush(old_size, new_size)
      when is_integer(old_size) and is_integer(new_size) do
    Native.nif_tiles_to_flush(old_size, new_size)
  end

  @doc """
  Entry-bundle paths that must be (re)written when growing from `old_size` to
  `new_size`. Returns `{:ok, [path]}` or `{:error, reason}`.
  """
  @spec entry_bundles_to_flush(non_neg_integer(), non_neg_integer()) ::
          {:ok, [String.t()]} | {:error, String.t()}
  def entry_bundles_to_flush(old_size, new_size)
      when is_integer(old_size) and is_integer(new_size) do
    Native.nif_entry_bundles_to_flush(old_size, new_size)
  end

  @doc """
  Every tile path needed to represent a tree of `size` leaves.
  """
  @spec tiles_for_size(non_neg_integer()) :: [String.t()]
  def tiles_for_size(size) when is_integer(size) do
    Native.nif_tiles_for_size(size)
  end

  @doc """
  Width (number of leaves, `1..256`) of the partial tile at `level` for a tree
  of `size` leaves; `0` if that tile is absent.
  """
  @spec partial_width(0..63, non_neg_integer()) :: 0..256
  def partial_width(level, size)
      when is_integer(level) and level in 0..63 and is_integer(size) do
    Native.nif_partial_width(level, size)
  end

  @doc """
  Parse the node hashes out of a tile's bytes.

  `bytes` is the base64-encoded tile blob; `level`/`index`/`width` identify the
  tile. Returns `{:ok, [hash_b64]}` (each 32 bytes, base64) or
  `{:error, reason}`. Runs on a dirty CPU scheduler.
  """
  @spec tile_hashes(0..63, non_neg_integer(), 1..256, String.t()) ::
          {:ok, [String.t()]} | {:error, String.t()}
  def tile_hashes(level, index, width, bytes_b64)
      when is_integer(level) and is_integer(index) and is_integer(width) and
             is_binary(bytes_b64) do
    Native.nif_tile_hashes(level, index, width, bytes_b64)
  end

  @doc """
  Recompute the RFC 6962 Merkle root from an ordered list of base64 **leaf
  hashes**. Returns `{:ok, root_b64}` or `{:error, reason}`. Dirty CPU.
  """
  @spec recompute_root([String.t()]) :: {:ok, String.t()} | {:error, String.t()}
  def recompute_root(leaf_hashes_b64) when is_list(leaf_hashes_b64) do
    Native.nif_recompute_root(leaf_hashes_b64)
  end

  @doc """
  Compute the parent hash above a full tile's `256` (or fewer, for a partial
  tile) node hashes. Returns `{:ok, hash_b64}` or `{:error, reason}`. Dirty CPU.
  """
  @spec parent_hash([String.t()]) :: {:ok, String.t()} | {:error, String.t()}
  def parent_hash(tile_hashes_b64) when is_list(tile_hashes_b64) do
    Native.nif_parent_hash(tile_hashes_b64)
  end
end
