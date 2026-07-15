defmodule MetamorphicLog.CrossLanguageKatTest do
  @moduledoc """
  NIF leg of the cross-language byte-parity KAT (#336 / #335 Slice 6).

  Mirrors `metamorphic-log/tests/cross_language.rs` value-for-value. Because the
  NIF (like the WASM layer) is a logic-free shell over the rlib, reproducing the
  same locked vectors *through the NIF boundary* proves the Elixir client
  computes byte-identically to the Rust core and the browser WASM SDK.

  ML-DSA signing is hedged, so — exactly as in the native/WASM suites — we lock
  *verification* and the deterministic vkey / canonical bytes, never regenerated
  signature bytes.
  """
  use ExUnit.Case, async: true

  alias MetamorphicLog.{Checkpoint, Commitment, Coniks, Ingest, Leaf, Note, Policy, Proof}
  alias MetamorphicLog.Vectors, as: V

  describe "RFC 6962 inclusion / consistency (verification + monitor core)" do
    test "inclusion reference vector verifies" do
      assert :ok = Proof.verify_inclusion(0, 8, V.leaf0_b64(), V.proof0_8(), V.root8_b64())
      assert Proof.valid_inclusion?(0, 8, V.leaf0_b64(), V.proof0_8(), V.root8_b64())
    end

    test "inclusion rejects a tampered root" do
      <<first, rest::binary>> = Base.decode64!(V.root8_b64())
      bad_root = Base.encode64(<<Bitwise.bxor(first, 1), rest::binary>>)
      assert {:error, _} = Proof.verify_inclusion(0, 8, V.leaf0_b64(), V.proof0_8(), bad_root)
    end

    test "consistency reference vector verifies (size 1 -> 8)" do
      root1 = V.leaf0_b64()
      assert :ok = Proof.verify_consistency(1, 8, V.proof0_8(), root1, V.root8_b64())
    end

    test "consistency rejects equivocation" do
      root1 = V.leaf0_b64()
      <<first, rest::binary>> = Base.decode64!(V.root8_b64())
      bad = Base.encode64(<<Bitwise.bxor(first, 1), rest::binary>>)
      assert {:error, _} = Proof.verify_consistency(1, 8, V.proof0_8(), root1, bad)
    end
  end

  describe "Layer-0 canonical leaf: mosslet/key-history/v1 byte parity" do
    test "genesis canonical byte length is locked" do
      {:ok, canon} = Leaf.key_history_v1_canonical_bytes(V.genesis_entry())
      assert byte_size(Base.decode64!(canon)) == V.kat_genesis_canon_size()
    end

    test "genesis entry hash matches native KAT" do
      assert {:ok, hash} = Leaf.key_history_v1_entry_hash(V.genesis_entry())
      assert hash == V.kat_genesis_hash_b64()
    end

    test "rotation entry hash matches native KAT (chained via prev_entry_hash)" do
      assert {:ok, hash} = Leaf.key_history_v1_entry_hash(V.rotation_entry())
      assert hash == V.kat_rotation_hash_b64()
    end

    test "genesis RFC 6962 leaf hash matches native KAT" do
      assert {:ok, leaf} = Leaf.key_history_v1_rfc6962_leaf_hash(V.genesis_entry())
      assert Base.decode64!(leaf) == V.hex(V.kat_genesis_rfc6962_leaf_hex())
    end

    test "rotation RFC 6962 leaf hash matches native KAT" do
      assert {:ok, leaf} = Leaf.key_history_v1_rfc6962_leaf_hash(V.rotation_entry())
      assert Base.decode64!(leaf) == V.hex(V.kat_rotation_rfc6962_leaf_hex())
    end
  end

  describe "Layer-0 canonical leaf: context-parameterized (branded) entry hash" do
    test "mosslet label reproduces the frozen genesis entry hash byte-for-byte" do
      assert {:ok, hash} =
               Leaf.key_history_entry_hash_with_context(
                 "mosslet/key-history/v1",
                 V.genesis_entry()
               )

      assert hash == V.kat_genesis_hash_b64()
    end

    test "a different namespace label yields a different entry hash" do
      assert {:ok, mosslet} =
               Leaf.key_history_entry_hash_with_context(
                 "mosslet/key-history/v1",
                 V.genesis_entry()
               )

      assert {:ok, mosskeys} =
               Leaf.key_history_entry_hash_with_context(
                 "mosskeys/key-history/v1",
                 V.genesis_entry()
               )

      assert mosskeys != mosslet
      assert mosskeys != V.kat_genesis_hash_b64()
    end

    test "canonical bytes and RFC 6962 leaf hash are brand-independent" do
      # The label only feeds the intra-chain entry hash; the canonical encoding
      # and the Merkle leaf hash are computed without it, so both are identical
      # regardless of which namespace brands the chain.
      assert {:ok, canon} = Leaf.key_history_v1_canonical_bytes(V.genesis_entry())
      assert byte_size(Base.decode64!(canon)) == V.kat_genesis_canon_size()

      assert {:ok, leaf} = Leaf.key_history_v1_rfc6962_leaf_hash(V.genesis_entry())
      assert Base.decode64!(leaf) == V.hex(V.kat_genesis_rfc6962_leaf_hex())
    end

    test "bang form matches the reference vector" do
      assert Leaf.key_history_entry_hash_with_context!(
               "mosslet/key-history/v1",
               V.genesis_entry()
             ) == V.kat_genesis_hash_b64()
    end

    test "a malformed context label returns an error" do
      assert {:error, _} =
               Leaf.key_history_entry_hash_with_context("missing-version", V.genesis_entry())
    end
  end

  describe "Checkpoint / signed-note: classical + additive hybrid-PQ (verify-locked)" do
    test "verify_signed_note accepts the hybrid KAT note" do
      assert {:ok, 1} = Note.verify(V.hybrid_kat_note(), [V.hybrid_kat_vkey()])
      assert Note.verified?(V.hybrid_kat_note(), [V.hybrid_kat_vkey()])
    end

    test "checkpoint_verify parses the hybrid KAT head" do
      assert {:ok, %Checkpoint{origin: origin, size: size, root: root}} =
               Checkpoint.verify(V.hybrid_kat_note(), [V.hybrid_kat_vkey()])

      assert origin == "metamorphic.app/kat"
      assert size == 10
      assert root == V.kat_checkpoint_root_b64()
    end

    test "signed note rejects an untrusted (empty) keyset" do
      assert {:error, _} = Note.verify(V.hybrid_kat_note(), [])
    end

    test "signed note rejects a tampered body" do
      <<_first::binary-size(1), rest::binary>> = V.hybrid_kat_note()
      tampered = "X" <> rest
      assert {:error, _} = Note.verify(tampered, [V.hybrid_kat_vkey()])
    end
  end

  describe "NamespacePolicy: parse + verify + declared == observed" do
    test "signed policy verify matches native KAT" do
      assert {:ok, policy} = Policy.verify(V.signed_policy_b64())
      assert policy.namespace == "metamorphic.app"
      assert policy.security_level == :cat3
      assert policy.checkpoint_suite == :hybrid
      assert policy.commitment_hash == :sha3_256
      assert policy.vrf_mode == :classical
      assert Base.decode64!(policy.policy_hash) == V.hex(V.kat_policy_hash_hex())
    end

    test "signed policy verify rejects tamper" do
      bytes = Base.decode64!(V.signed_policy_b64())
      n = byte_size(bytes)
      head = binary_part(bytes, 0, n - 1)
      last = :binary.at(bytes, n - 1)
      tampered = Base.encode64(head <> <<Bitwise.bxor(last, 1)>>)
      assert {:error, _} = Policy.verify(tampered)
    end

    test "enforce commitment hash: declared (Cat-3 => sha3_256) == observed" do
      assert :ok = Policy.enforce_commitment_hash(V.signed_policy_b64(), :sha3_256)
      assert {:error, _} = Policy.enforce_commitment_hash(V.signed_policy_b64(), :sha3_512)
    end

    test "enforce VRF suite id: classical mode expects ECVRF suite 0x03" do
      assert :ok = Policy.enforce_vrf_suite_id(V.signed_policy_b64(), 0x03)
      assert {:error, _} = Policy.enforce_vrf_suite_id(V.signed_policy_b64(), 0x04)
    end
  end

  describe "CONIKS: commitment vector + verifier routing" do
    test "verify_commitment matches the fixed-opening vector" do
      commitment = Base.encode64(V.hex(V.commitment_vec_hex()))
      opening = Base.encode64(:binary.copy(<<7>>, 32))
      value = Base.encode64("value-bytes")
      assert :ok = Commitment.verify(V.commitment_ctx(), commitment, value, opening)
      assert Commitment.valid?(V.commitment_ctx(), commitment, value, opening)
    end

    test "verify_commitment rejects the wrong value" do
      commitment = Base.encode64(V.hex(V.commitment_vec_hex()))
      opening = Base.encode64(:binary.copy(<<7>>, 32))
      wrong = Base.encode64("WRONG-bytes")
      assert {:error, _} = Commitment.verify(V.commitment_ctx(), commitment, wrong, opening)
    end

    test "coniks verify rejects malformed proofs (positive proofs are prover-produced)" do
      garbage = Base.encode64(<<0, 1, 2, 3>>)
      vrf_pub = Base.encode64(:binary.copy(<<0>>, 32))
      root = Base.encode64(:binary.copy(<<0>>, 64))
      identity = Base.encode64("alice@example.com")

      assert {:error, _} =
               Coniks.verify_lookup("mosslet", vrf_pub, root, identity, garbage)

      assert {:error, _} =
               Coniks.verify_absence("mosslet", vrf_pub, root, identity, garbage)
    end
  end

  describe "Ingestion primitives" do
    test "dedup key from record matches the native KAT (acme / \"hello\")" do
      assert {:ok, key_b64} = Ingest.dedup_key_from_record("acme", Base.encode64("hello"))

      assert Base.encode16(Base.decode64!(key_b64), case: :lower) ==
               "96a863d339a97f0870c8a72c7bd6dbc96187928e77035ce98d5c43d99fcd9d3c" <>
                 "b6b7daf59a70320251e5acf09a5477bf0d8177ce16f00977062df3c8c6ea1f16"
    end

    test "recompute_root of a single leaf is the leaf hash itself" do
      assert {:ok, root} = Ingest.recompute_root([V.leaf0_b64()])
      assert root == V.leaf0_b64()
    end

    test "flush geometry returns tile paths" do
      assert {:ok, tiles} = Ingest.tiles_to_flush(0, 300)
      assert is_list(tiles)
      assert "tile/0/000" in tiles
    end

    test "partial_width is in range" do
      assert Ingest.partial_width(0, 300) in 0..256
    end
  end
end
