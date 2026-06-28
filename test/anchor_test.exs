defmodule MetamorphicLog.AnchorTest do
  @moduledoc """
  Exercises the Slice 8 anchoring surface through the NIF boundary: canonical
  record round-trip, the medium-independent commitment, the Layer-0 leaf hash,
  and the `verify_anchored` binding gate against the locked hybrid checkpoint
  KAT. The deep consistency-between-anchors audit is locked in the Rust core's
  `tests/anchoring.rs`; here we prove the Elixir client forwards to it and
  computes the canonical bytes byte-identically across the boundary.
  """
  use ExUnit.Case, async: true

  alias MetamorphicLog.Anchor
  alias MetamorphicLog.Vectors, as: V

  # The hybrid checkpoint KAT head: origin "metamorphic.app/kat", size 10.
  defp head_origin, do: "metamorphic.app/kat"
  defp head_size, do: 10
  defp head_root, do: V.kat_checkpoint_root_b64()

  defp record(opts \\ []) do
    medium = Keyword.get(opts, :medium, "ethereum/mainnet")
    locator = Keyword.get(opts, :locator, Base.encode64("0xdeadbeef"))
    size = Keyword.get(opts, :size, head_size())

    {:ok, rec} = Anchor.record_canonical_bytes(head_origin(), size, head_root(), medium, locator)
    rec
  end

  describe "record canonical bytes + parse" do
    test "round-trips byte-for-byte through parse" do
      rec = record(medium: "rfc3161", locator: Base.encode64("receipt-7"))

      assert {:ok, parsed} = Anchor.parse_record(rec)
      assert parsed.origin == head_origin()
      assert parsed.size == head_size()
      assert parsed.root == head_root()
      assert parsed.commitment_alg == "sha3_512"
      assert parsed.medium == "rfc3161"
      assert parsed.locator == Base.encode64("receipt-7")

      # Re-encoding the parsed fields yields identical bytes.
      assert {:ok, ^rec} =
               Anchor.record_canonical_bytes(
                 parsed.origin,
                 parsed.size,
                 parsed.root,
                 parsed.medium,
                 parsed.locator
               )
    end

    test "rejects an unknown commitment algorithm" do
      assert {:error, reason} =
               Anchor.record_canonical_bytes(
                 head_origin(),
                 head_size(),
                 head_root(),
                 "ethereum/mainnet",
                 Base.encode64("x"),
                 "blake3"
               )

      assert reason =~ "commitment algorithm"
    end

    test "rejects a malformed medium and an empty locator" do
      assert {:error, _} =
               Anchor.record_canonical_bytes(
                 head_origin(),
                 head_size(),
                 head_root(),
                 "has space",
                 Base.encode64("x")
               )

      assert {:error, _} =
               Anchor.record_canonical_bytes(
                 head_origin(),
                 head_size(),
                 head_root(),
                 "ethereum/mainnet",
                 Base.encode64("")
               )
    end

    test "parse rejects malformed bytes" do
      assert {:error, _} = Anchor.parse_record(Base.encode64(<<0, 0, 0, 1>>))

      # Trailing bytes after a valid record.
      rec_bytes = Base.decode64!(record())
      assert {:error, _} = Anchor.parse_record(Base.encode64(rec_bytes <> <<0xFF>>))
    end
  end

  describe "anchor commitment (medium-independent)" do
    test "is 64 bytes (SHA3-512) and identical across medium/locator for the same head" do
      on_chain = record(medium: "ethereum/mainnet", locator: Base.encode64("tx-1"))
      on_notary = record(medium: "rfc3161", locator: Base.encode64("receipt-2"))

      assert {:ok, c1} = Anchor.anchor_commitment(on_chain)
      assert {:ok, c2} = Anchor.anchor_commitment(on_notary)

      assert byte_size(Base.decode64!(c1)) == 64
      assert c1 == c2
    end

    test "differs for a different head" do
      assert {:ok, c} = Anchor.anchor_commitment(record(size: head_size()))
      assert {:ok, other} = Anchor.anchor_commitment(record(size: head_size() + 1))
      refute c == other
    end
  end

  describe "rfc6962 leaf hash" do
    test "is a stable 32-byte hash" do
      rec = record()
      assert {:ok, leaf} = Anchor.rfc6962_leaf_hash(rec)
      assert byte_size(Base.decode64!(leaf)) == 32
      assert {:ok, ^leaf} = Anchor.rfc6962_leaf_hash(rec)
    end
  end

  describe "verify_commitment (medium-side check)" do
    test "accepts the recomputed commitment and rejects a mismatch" do
      rec = record()
      {:ok, commitment} = Anchor.anchor_commitment(rec)

      assert :ok = Anchor.verify_commitment(rec, commitment)

      tampered = Base.encode64(:binary.copy(<<0>>, 64))
      assert {:error, :commitment_mismatch} = Anchor.verify_commitment(rec, tampered)
    end
  end

  describe "verify_anchored (binding gate)" do
    test "accepts a record that binds the verified checkpoint head" do
      rec = record()
      assert :ok = Anchor.verify_anchored(V.hybrid_kat_note(), [V.hybrid_kat_vkey()], rec)
    end

    test "rejects a record bound to a different head" do
      mismatched = record(size: head_size() + 1)

      assert {:error, _} =
               Anchor.verify_anchored(V.hybrid_kat_note(), [V.hybrid_kat_vkey()], mismatched)
    end

    test "rejects when the checkpoint note is untrusted" do
      assert {:error, _} = Anchor.verify_anchored(V.hybrid_kat_note(), [], record())
    end
  end
end
