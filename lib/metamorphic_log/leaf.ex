defmodule MetamorphicLog.Leaf do
  @moduledoc """
  Canonical leaf encoding for the `mosslet/key-history/v1` conformance instance.

  This is the worked example of the engine's application-agnostic leaf layer: a
  signed, hash-chained key-history entry. The three functions here reproduce —
  **byte-for-byte** — the canonical encoding, the intra-chain entry hash, and
  the RFC 6962 leaf hash, identically across the Rust core, the browser WASM
  SDK, and this NIF. That cross-target parity is what lets a monitor recompute
  and compare a log built by browser clients.

  ## Branding your own key history (recommended)

  `mosslet/key-history/v1` is the reference conformance instance, not a label
  you should reuse. For your own application, brand the chain with your own
  `<namespace>/key-history/v1` label via
  `key_history_entry_hash_with_context/2` — for example
  `"mosskeys/key-history/v1"`. That domain-separates your entry hashes and lets
  auditors tell whose key history a chain is, while the canonical bytes and the
  RFC 6962 leaf hash stay brand-independent, so cross-target parity is
  preserved. The `key_history_v1_*` functions remain for reproducing the frozen
  reference vectors exactly.

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
  Context-parameterized intra-chain entry hash — the **recommended** way to
  compute a key-history `entry_hash`.

  Brand the chain with your own `<namespace>/key-history/v1` label (for example
  `"mosskeys/key-history/v1"`) instead of inheriting the reference
  `mosslet/key-history/v1` instance. Tailoring the label to your namespace
  domain-separates your entry hashes and lets an auditor tell whose key history
  a chain belongs to, while the canonical bytes and the RFC 6962 leaf hash stay
  brand-independent — a monitor recomputes them identically regardless of label.

  `context` is a `<namespace>/<record-type>/v<major>` label, validated before it
  crosses the NIF boundary; a malformed label returns `{:error, reason}`.
  Passing exactly `"mosslet/key-history/v1"` reproduces
  `key_history_v1_entry_hash/1` byte-for-byte.

  ## Example

      {:ok, hash} =
        MetamorphicLog.Leaf.key_history_entry_hash_with_context(
          "mosskeys/key-history/v1",
          entry
        )

  """
  @spec key_history_entry_hash_with_context(String.t(), entry()) ::
          {:ok, String.t()} | {:error, String.t()}
  def key_history_entry_hash_with_context(context, entry)
      when is_binary(context) and is_map(entry) do
    {seq, ts_ms, x, pq, sp, prev} = unpack(entry)
    Native.nif_key_history_entry_hash_with_context(context, seq, ts_ms, x, pq, sp, prev)
  end

  @doc "Bang form of `key_history_entry_hash_with_context/2`."
  @spec key_history_entry_hash_with_context!(String.t(), entry()) :: String.t()
  def key_history_entry_hash_with_context!(context, entry),
    do: unwrap!(key_history_entry_hash_with_context(context, entry))

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
