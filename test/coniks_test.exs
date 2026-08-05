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

defmodule MetamorphicLog.ConiksPoprfTest do
  @moduledoc """
  POPRF-backed (RFC 9497) CONIKS directories: the operator builds the tree from
  cleartext labels (non-oblivious `Evaluate`), then serves **only** blinded
  evaluations and by-index lookups — the query-time cleartext-label exposure is
  gone. These tests drive the full oblivious client flow through the NIF
  (`MetamorphicCrypto.Poprf`) and assert byte-parity with the RFC 9497 vectors
  for the deterministic server-side pieces.
  """

  use ExUnit.Case, async: true

  alias MetamorphicCrypto.Poprf
  alias MetamorphicLog.Coniks

  @namespace "metamorphic.app-poprf-test"
  @info Base.encode64("mosskeys/directory/v1:poprf-test")

  # RFC 9497 A.1.3 key material (see MetamorphicCrypto.PoprfTest).
  @seed "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
  @key_info "74657374206b6579"
  @pk_sm "c647bef38497bc6ec077c22af65b696efa43bff3b4a1975a3e8e0a1c5a79d631"

  defp b64(hex), do: hex |> Base.decode16!(case: :lower) |> Base.encode64()

  defp open do
    {:ok, {secret_b64, public_b64}} = Coniks.derive_poprf_key_pair(b64(@seed), b64(@key_info))
    assert public_b64 == b64(@pk_sm)
    {:ok, dir} = Coniks.directory_open_poprf(@namespace, @info, secret_b64)
    {dir, public_b64}
  end

  # The oblivious client flow, exactly as a browser/CLI relying party runs it.
  defp derive_index(dir, public_b64, identity) do
    identity_b64 = Base.encode64(identity)

    {:ok, %{blind: blind, blinded_element: blinded, tweaked_key: tweaked}} =
      Poprf.blind(identity_b64, @info, public_b64)

    {:ok, {evaluated, proof}} = Coniks.blind_evaluate(dir, blinded)

    {:ok, output} =
      Poprf.finalize(identity_b64, blind, evaluated, blinded, proof, @info, tweaked)

    output |> Base.decode64!() |> binary_part(0, 32) |> Base.encode64()
  end

  test "directory params: suite id, public key, info" do
    {dir, public_b64} = open()

    assert {:ok, 0x80} = Coniks.suite_id(dir)
    assert {:ok, ^public_b64} = Coniks.poprf_public(dir)
    assert {:ok, @info} = Coniks.poprf_info(dir)
    assert {:error, _} = Coniks.vrf_public(dir)
  end

  test "cleartext lookup is rejected on a POPRF directory" do
    {dir, _pk} = open()
    :ok = Coniks.insert(dir, Base.encode64("alice"), Base.encode64("v"))

    assert {:error, reason} = Coniks.lookup(dir, Base.encode64("alice"))
    assert reason =~ "POPRF"
  end

  test "oblivious round trip: present and absent verify by index" do
    {dir, public_b64} = open()
    :ok = Coniks.insert(dir, Base.encode64("alice"), Base.encode64("alice-value"))
    :ok = Coniks.insert(dir, Base.encode64("bob"), Base.encode64("bob-value"))
    {:ok, root_b64} = Coniks.root(dir)
    {:ok, suite_id} = Coniks.suite_id(dir)

    # Presence: alice's obliviously derived index lands on her leaf.
    index_b64 = derive_index(dir, public_b64, "alice")

    assert {:ok, {:present, value_b64, proof_b64}} = Coniks.lookup_by_index(dir, index_b64)
    assert value_b64 == Base.encode64("alice-value")

    assert {:ok, ^value_b64} =
             Coniks.verify_indexed_lookup(@namespace, suite_id, root_b64, index_b64, proof_b64)

    # Absence: carol's derived index holds the empty leaf.
    absent_b64 = derive_index(dir, public_b64, "carol")

    assert {:ok, {:absent, proof_b64}} = Coniks.lookup_by_index(dir, absent_b64)

    assert :ok =
             Coniks.verify_indexed_absence(@namespace, suite_id, root_b64, absent_b64, proof_b64)
  end

  test "a tampered root or wrong index is rejected" do
    {dir, public_b64} = open()
    :ok = Coniks.insert(dir, Base.encode64("alice"), Base.encode64("v"))
    {:ok, root_b64} = Coniks.root(dir)
    {:ok, suite_id} = Coniks.suite_id(dir)

    index_b64 = derive_index(dir, public_b64, "alice")
    {:ok, {:present, _value, proof_b64}} = Coniks.lookup_by_index(dir, index_b64)

    bad_root = Base.encode64(:binary.copy(<<0>>, 64))

    assert {:error, _} =
             Coniks.verify_indexed_lookup(@namespace, suite_id, bad_root, index_b64, proof_b64)

    other_b64 = derive_index(dir, public_b64, "mallory")

    assert {:error, _} =
             Coniks.verify_indexed_lookup(@namespace, suite_id, root_b64, other_b64, proof_b64)
  end

  test "a VRF directory rejects blind evaluation" do
    {:ok, {secret_b64, _public_b64}} = Coniks.generate_vrf_key()
    {:ok, dir} = Coniks.directory_open(@namespace, secret_b64)

    assert {:error, _} = Coniks.blind_evaluate(dir, Base.encode64(<<0::256>>))
    assert {:error, _} = Coniks.poprf_public(dir)
  end
end
