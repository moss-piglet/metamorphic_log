defmodule MetamorphicLog.Leaf do
  @moduledoc """
  Canonical leaf encoding for the `mosslet/key-history/v1` conformance instance.

  This is the worked example of the engine's application-agnostic leaf layer: a
  signed, hash-chained key-history entry. The three functions here reproduce —
  **byte-for-byte** — the canonical encoding, the intra-chain entry hash, and
  the RFC 6962 leaf hash, identically across the Rust core, the browser WASM
  SDK, and this NIF. That cross-target parity is what lets a monitor recompute
  and compare a log built by browser clients.

  ## Entry

  An entry is a map with base64-encoded binary fields:

      %{
        seq: 0,                     # u64 sequence number
        ts_ms: 1_700_000_000_000,   # u64 unix-ms timestamp
        enc_x25519: "...",          # base64 X25519 encryption public key
        enc_pq: "...",              # base64 ML-KEM encryption public key
        signing_pub: "...",         # base64 hybrid signing public key
        prev_entry_hash: nil        # base64 prev entry_hash, or nil for genesis
      }

  ## Canonical layout

      u32_be(VERSION=1)
        || u64_be(seq) || u64_be(ts_ms)
        || lp(enc_x25519) || lp(enc_pq) || lp(signing_pub) || lp(prev_entry_hash)

  where `lp(x) = u32_be(byte_size(x)) || x` and a `nil` `prev_entry_hash`
  encodes as `lp(<<>>)`.

  ## Return shape

  Each function returns `{:ok, value_b64} | {:error, reason}`, with a `!`
  variant that returns the value directly and raises on invalid input.
  """

  alias MetamorphicLog.Native

  @typedoc """
  A `mosslet/key-history/v1` entry with base64-encoded binary fields.
  `:prev_entry_hash` is `nil` for the genesis entry.
  """
  @type entry :: %{
          required(:seq) => non_neg_integer(),
          required(:ts_ms) => non_neg_integer(),
          required(:enc_x25519) => String.t(),
          required(:enc_pq) => String.t(),
          required(:signing_pub) => String.t(),
          optional(:prev_entry_hash) => String.t() | nil
        }

  @doc """
  Canonical byte encoding of a `key-history/v1` `entry`, base64-encoded.

  ## Example

      {:ok, canon} = MetamorphicLog.Leaf.key_history_v1_canonical_bytes(entry)

  """
  @spec key_history_v1_canonical_bytes(entry()) :: {:ok, String.t()} | {:error, String.t()}
  def key_history_v1_canonical_bytes(entry) when is_map(entry) do
    {seq, ts_ms, x, pq, sp, prev} = unpack(entry)
    Native.nif_key_history_v1_canonical_bytes(seq, ts_ms, x, pq, sp, prev)
  end

  @doc "Bang form of `key_history_v1_canonical_bytes/1`."
  @spec key_history_v1_canonical_bytes!(entry()) :: String.t()
  def key_history_v1_canonical_bytes!(entry),
    do: unwrap!(key_history_v1_canonical_bytes(entry))

  @doc """
  Intra-chain SHA3-512 entry hash of `entry`, base64-encoded.

  This is the value a later entry references as its `:prev_entry_hash`, chaining
  the history together.
  """
  @spec key_history_v1_entry_hash(entry()) :: {:ok, String.t()} | {:error, String.t()}
  def key_history_v1_entry_hash(entry) when is_map(entry) do
    {seq, ts_ms, x, pq, sp, prev} = unpack(entry)
    Native.nif_key_history_v1_entry_hash(seq, ts_ms, x, pq, sp, prev)
  end

  @doc "Bang form of `key_history_v1_entry_hash/1`."
  @spec key_history_v1_entry_hash!(entry()) :: String.t()
  def key_history_v1_entry_hash!(entry), do: unwrap!(key_history_v1_entry_hash(entry))

  @doc """
  RFC 6962 leaf hash — `SHA-256(0x00 || canonical_bytes)` — of `entry`,
  base64-encoded. This is the value placed in the Merkle tree.
  """
  @spec key_history_v1_rfc6962_leaf_hash(entry()) :: {:ok, String.t()} | {:error, String.t()}
  def key_history_v1_rfc6962_leaf_hash(entry) when is_map(entry) do
    {seq, ts_ms, x, pq, sp, prev} = unpack(entry)
    Native.nif_key_history_v1_rfc6962_leaf_hash(seq, ts_ms, x, pq, sp, prev)
  end

  @doc "Bang form of `key_history_v1_rfc6962_leaf_hash/1`."
  @spec key_history_v1_rfc6962_leaf_hash!(entry()) :: String.t()
  def key_history_v1_rfc6962_leaf_hash!(entry),
    do: unwrap!(key_history_v1_rfc6962_leaf_hash(entry))

  # ─── Internal ────────────────────────────────────────────────────────────

  defp unpack(entry) do
    {
      Map.fetch!(entry, :seq),
      Map.fetch!(entry, :ts_ms),
      Map.fetch!(entry, :enc_x25519),
      Map.fetch!(entry, :enc_pq),
      Map.fetch!(entry, :signing_pub),
      Map.get(entry, :prev_entry_hash)
    }
  end

  defp unwrap!({:ok, value}), do: value
  defp unwrap!({:error, reason}), do: raise("key-history leaf encoding failed: #{reason}")
end
