defmodule MetamorphicLog.Vectors do
  @moduledoc false
  # Shared known-answer-test (KAT) fixtures for the NIF leg of the
  # cross-language byte-parity suite. These mirror, value-for-value, the
  # constants in the engine's `tests/cross_language.rs` (Rust core <-> WASM),
  # so reproducing them through the NIF proves byte-identical computation
  # across Rust core / WASM / Elixir NIF.

  @vectors_dir Path.join(__DIR__, "vectors")

  # ── Canonical leaf (mosslet/key-history/v1) — tests/conformance.rs ──────────
  def genesis_ts, do: 1_700_000_000_000
  def rotation_ts, do: 1_700_000_100_000

  def x_a, do: for(i <- 0..31, into: <<>>, do: <<rem(i * 7 + 1, 256)>>)
  def x_b, do: for(i <- 0..31, into: <<>>, do: <<rem(i * 5 + 3, 256)>>)
  def pq_a, do: for(i <- 0..1599, into: <<>>, do: <<rem(i, 256)>>)
  def sp_fixed, do: for(i <- 0..2624, into: <<>>, do: <<rem(i * 3, 256)>>)

  def kat_genesis_hash_b64,
    do: "ueTkShE9EQ1ROe8DFVa0m706AJPrsJyLGt2uSSzmStPty0xtu3gX2zjvBNdgA9swPWYEXx+wEsjDNXbOmzhJFA=="

  def kat_rotation_hash_b64,
    do: "14CrClVh3k5BrmUQT9FZ3UnE1wZG9820t3eXynXXMwmk6YV1V4ykoCiT79HA1BCWKtq6VU4SYEflZMYeRZoJjQ=="

  def kat_genesis_canon_size, do: 4293

  def kat_genesis_rfc6962_leaf_hex,
    do: "a429552cdc9dba9b9bc733d2afe0e1beb5f5100184ea8416179dd0d4fd864263"

  def kat_rotation_rfc6962_leaf_hex,
    do: "cca5a60048d9c76681a02c7856d310af9c24188a226c4ec1e0cc5f451f95fe35"

  def genesis_entry do
    %{
      seq: 0,
      ts_ms: genesis_ts(),
      enc_x25519: Base.encode64(x_a()),
      enc_pq: Base.encode64(pq_a()),
      signing_pub: Base.encode64(sp_fixed()),
      prev_entry_hash: nil
    }
  end

  def rotation_entry do
    %{
      seq: 1,
      ts_ms: rotation_ts(),
      enc_x25519: Base.encode64(x_b()),
      enc_pq: Base.encode64(pq_a()),
      signing_pub: Base.encode64(sp_fixed()),
      prev_entry_hash: kat_genesis_hash_b64()
    }
  end

  # ── RFC 6962 8-leaf corpus (transparency-dev/merkle) ────────────────────────
  def root8_b64, do: "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg="
  def leaf0_b64, do: "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0="

  def proof0_8,
    do: [
      "lqKW0iTyhcZ77pPDD4owkVfw2qNdxbh+QQt4YwoJz8c=",
      "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=",
      "a0eq8p7jwq+a+Im8H7klTavTEXfxYjLdaqsDXKOb9uQ="
    ]

  # ── Commitment fixed-opening vector — tests/coniks_vectors.rs ───────────────
  def commitment_ctx, do: "mosslet/coniks-commitment/v1"

  def commitment_vec_hex,
    do:
      "21d390c8041326c07dcca27f95e49cffc1bab834b71059f9421711b4785cda58" <>
        "79d6132c6df9eb736128f815854adad599859c4e2d2b20e26d30b2227663bf80"

  # ── NamespacePolicy KAT — tests/namespace_policy.rs ─────────────────────────
  def kat_policy_hash_hex,
    do:
      "e025dd924f7fb976d3283c48b7c3cf9573eaca158f4772205f43586aae64dbe3" <>
        "8c2a3df75de681610ca602ab802dc60306a1398e7591640bf16d3ea6ae8d2e97"

  def signed_policy_b64,
    do: @vectors_dir |> Path.join("namespace_policy_signed.b64") |> File.read!() |> String.trim()

  # ── Hybrid checkpoint/note KAT — tests/pq_checkpoint.rs ──────────────────────
  def hybrid_kat_note,
    do:
      @vectors_dir
      |> Path.join("hybrid_kat_note.b64")
      |> File.read!()
      |> String.trim()
      |> Base.decode64!()

  # The deterministic hybrid verifier key (vkey bytes are deterministic; only the
  # ML-DSA signature bytes are hedged). Lifted verbatim from pq_checkpoint.rs.
  def hybrid_kat_vkey,
    do:
      "metamorphic.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"

  def kat_checkpoint_root_b64, do: "q1bnDR7DLfXk0sCC5tD4hbsBLg7p+9Gd4tT8H9wYnKE="

  def hex(s), do: Base.decode16!(s, case: :lower)

  # ── KEYTRANS movable golden vectors (KEYTRANS_EXP_04) — Slice 9 ─────────────
  # Rust-generated (crate 0.1.4) search / fixed-version / monitor proofs for all
  # three §15.1 suites. Movable: NOT in the frozen KAT set. See the fixture file
  # header. Loaded once, at compile time, from the committed data file.
  @keytrans_fixtures @vectors_dir
                     |> Path.join("keytrans_movable_fixtures.exs")
                     |> Code.eval_file()
                     |> elem(0)

  def keytrans_fixtures, do: @keytrans_fixtures
end
