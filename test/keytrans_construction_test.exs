defmodule MetamorphicLog.KeytransConstructionTest do
  @moduledoc """
  Operator ↔ verifier round-trips for the KEYTRANS directory construction
  surface (experimental / movable wire).

  Build a per-namespace directory from a fresh VRF secret, append label
  versions, then assert the greatest-version search proofs it produces verify
  against the published VRF public key and combined-tree root via the existing
  verifier API — and that tamper cases are rejected. The proof bytes never leave
  the library, so this locks the full producer→consumer loop across every suite.
  """

  use ExUnit.Case, async: true

  alias MetamorphicLog.Keytrans

  @context "metamorphic.app/keytrans-commitment/v1"

  # Commitment opening width per suite (`Nc`): 16 bytes for the on-spec standard
  # suites, 32 for the experimental hybrid-PQ suite.
  defp opening_len(:metamorphic_hybrid_exp), do: 32
  defp opening_len(_standard), do: 16

  defp opening(suite, tag), do: Base.encode64(:binary.copy(<<tag>>, opening_len(suite)))

  defp build(suite) do
    {:ok, {secret_b64, public_b64}} = Keytrans.generate_vrf_key(suite)
    {:ok, dir} = Keytrans.directory_open(suite, @context, secret_b64)

    assert {:ok, 0} =
             Keytrans.update(
               dir,
               Base.encode64("alice"),
               Base.encode64("v0"),
               1_000,
               opening(suite, 1)
             )

    assert {:ok, 1} =
             Keytrans.update(
               dir,
               Base.encode64("alice"),
               Base.encode64("v1"),
               2_000,
               opening(suite, 2)
             )

    assert {:ok, 0} =
             Keytrans.update(
               dir,
               Base.encode64("bob"),
               Base.encode64("bob-v0"),
               3_000,
               opening(suite, 3)
             )

    {:ok, root_b64} = Keytrans.combined_root(dir)
    {:ok, pub_from_dir} = Keytrans.directory_vrf_public(dir)
    assert pub_from_dir == public_b64

    %{dir: dir, public: public_b64, root: root_b64}
  end

  for suite <- [:kt128_sha256_p256, :kt128_sha256_ed25519, :metamorphic_hybrid_exp] do
    @suite suite

    test "#{suite}: a present label's greatest version verifies to its value" do
      ctx = build(@suite)

      assert {:ok, {:present, value_b64, proof_b64}} =
               Keytrans.prove_search(ctx.dir, Base.encode64("alice"))

      assert value_b64 == Base.encode64("v1")

      assert {:ok, {:present, ^value_b64}} =
               Keytrans.verify_search(
                 @suite,
                 @context,
                 ctx.public,
                 ctx.root,
                 Base.encode64("alice"),
                 proof_b64
               )
    end

    test "#{suite}: an absent label produces an absence proof that verifies" do
      ctx = build(@suite)

      assert {:ok, {:absent, proof_b64}} =
               Keytrans.prove_search(ctx.dir, Base.encode64("carol"))

      assert {:ok, :absent} =
               Keytrans.verify_search(
                 @suite,
                 @context,
                 ctx.public,
                 ctx.root,
                 Base.encode64("carol"),
                 proof_b64
               )
    end

    test "#{suite}: a search proof is rejected against a tampered root" do
      ctx = build(@suite)

      assert {:ok, {:present, _value, proof_b64}} =
               Keytrans.prove_search(ctx.dir, Base.encode64("alice"))

      bad_root = Base.encode64(:binary.copy(<<0>>, 32))

      assert {:error, _reason} =
               Keytrans.verify_search(
                 @suite,
                 @context,
                 ctx.public,
                 bad_root,
                 Base.encode64("alice"),
                 proof_b64
               )
    end
  end

  test "update mutates the combined-tree root" do
    suite = :kt128_sha256_ed25519
    {:ok, {secret_b64, _public}} = Keytrans.generate_vrf_key(suite)
    {:ok, dir} = Keytrans.directory_open(suite, @context, secret_b64)

    # An empty directory has no combined root.
    assert {:error, _} = Keytrans.combined_root(dir)

    assert {:ok, 0} =
             Keytrans.update(
               dir,
               Base.encode64("x"),
               Base.encode64("1"),
               1_000,
               opening(suite, 1)
             )

    {:ok, root_after} = Keytrans.combined_root(dir)

    assert {:ok, 1} =
             Keytrans.update(
               dir,
               Base.encode64("x"),
               Base.encode64("2"),
               2_000,
               opening(suite, 2)
             )

    {:ok, root_after2} = Keytrans.combined_root(dir)
    refute root_after2 == root_after
  end

  test "a wrong opening length is rejected" do
    suite = :kt128_sha256_p256
    {:ok, {secret_b64, _public}} = Keytrans.generate_vrf_key(suite)
    {:ok, dir} = Keytrans.directory_open(suite, @context, secret_b64)

    # 32 bytes is wrong for a standard suite (Nc = 16).
    wrong = Base.encode64(:binary.copy(<<0>>, 32))

    assert {:error, _} =
             Keytrans.update(dir, Base.encode64("alice"), Base.encode64("v"), 1_000, wrong)
  end

  test "a structurally invalid secret key is rejected" do
    assert {:error, _} =
             Keytrans.directory_open(:kt128_sha256_p256, @context, Base.encode64("too-short"))
  end
end
