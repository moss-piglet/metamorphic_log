defmodule MetamorphicLog.ConiksTest do
  @moduledoc """
  Operator ↔ verifier round-trips for the CONIKS directory construction surface.

  Build a per-namespace directory from a fresh VRF secret, append entries, then
  assert the presence/absence proofs it produces verify against the published
  VRF public key and directory root via the existing verifier APIs — and that
  tamper/foreign-namespace cases are rejected. The proof bytes never leave the
  library, so this locks the full producer→consumer loop.
  """

  use ExUnit.Case, async: true

  alias MetamorphicLog.Coniks

  @namespace "metamorphic.app-coniks-test"

  setup do
    {:ok, {secret_b64, public_b64}} = Coniks.generate_vrf_key()
    {:ok, dir} = Coniks.directory_open(@namespace, secret_b64)

    :ok = Coniks.insert(dir, Base.encode64("alice"), Base.encode64("alice-value"))
    :ok = Coniks.insert(dir, Base.encode64("bob"), Base.encode64("bob-value"))

    {:ok, root_b64} = Coniks.root(dir)
    {:ok, pub_from_dir} = Coniks.vrf_public(dir)

    # The directory-reported public key matches the one generate_vrf_key/0 gave.
    assert pub_from_dir == public_b64

    %{dir: dir, public: public_b64, root: root_b64}
  end

  test "a present identity produces a proof that verifies to its value", ctx do
    assert {:ok, {:present, value_b64, proof_b64}} =
             Coniks.lookup(ctx.dir, Base.encode64("alice"))

    assert value_b64 == Base.encode64("alice-value")

    assert {:ok, ^value_b64} =
             Coniks.verify_lookup(
               @namespace,
               ctx.public,
               ctx.root,
               Base.encode64("alice"),
               proof_b64
             )
  end

  test "an absent identity produces an absence proof that verifies", ctx do
    assert {:ok, {:absent, proof_b64}} = Coniks.lookup(ctx.dir, Base.encode64("carol"))

    assert :ok =
             Coniks.verify_absence(
               @namespace,
               ctx.public,
               ctx.root,
               Base.encode64("carol"),
               proof_b64
             )
  end

  test "a presence proof is rejected under the wrong namespace", ctx do
    assert {:ok, {:present, _value, proof_b64}} =
             Coniks.lookup(ctx.dir, Base.encode64("alice"))

    assert {:error, _reason} =
             Coniks.verify_lookup(
               "some-other-namespace",
               ctx.public,
               ctx.root,
               Base.encode64("alice"),
               proof_b64
             )
  end

  test "a presence proof is rejected against a tampered root", ctx do
    assert {:ok, {:present, _value, proof_b64}} =
             Coniks.lookup(ctx.dir, Base.encode64("alice"))

    bad_root = Base.encode64(:binary.copy(<<0>>, 64))

    assert {:error, _reason} =
             Coniks.verify_lookup(
               @namespace,
               ctx.public,
               bad_root,
               Base.encode64("alice"),
               proof_b64
             )
  end

  test "insert mutates the directory root" do
    {:ok, {secret_b64, _public_b64}} = Coniks.generate_vrf_key()
    {:ok, dir} = Coniks.directory_open(@namespace, secret_b64)
    {:ok, empty_root} = Coniks.root(dir)

    :ok = Coniks.insert(dir, Base.encode64("x"), Base.encode64("1"))
    {:ok, root_after} = Coniks.root(dir)
    refute root_after == empty_root

    # A second identity moves the root again (the commitment carries a fresh
    # random opening, so roots are not reproducible across directories by
    # design — only monotonic within one).
    :ok = Coniks.insert(dir, Base.encode64("y"), Base.encode64("2"))
    {:ok, root_after2} = Coniks.root(dir)
    refute root_after2 == root_after
  end

  test "malformed namespace and secret are rejected" do
    assert {:error, _} = Coniks.directory_open("has/slash", Base.encode64("whatever"))

    {:ok, {_secret, _public}} = Coniks.generate_vrf_key()
    assert {:error, _} = Coniks.directory_open(@namespace, Base.encode64("too-short"))
  end
end
