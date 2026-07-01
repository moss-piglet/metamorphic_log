defmodule MetamorphicLog.KeytransTest do
  @moduledoc """
  KEYTRANS combined-tree verification through the NIF, against Rust-generated
  golden vectors for all three §15.1 suites.

  These vectors are **movable** (`KEYTRANS_EXP_04`): they track the IETF draft
  wire and are intentionally excluded from the frozen cross-language KAT set.
  Verifying them through the NIF proves the Elixir client checks byte-identically
  to the Rust core and the browser WASM SDK.
  """
  use ExUnit.Case, async: true

  alias MetamorphicLog.Keytrans
  alias MetamorphicLog.Vectors, as: V

  @suites [:metamorphic_hybrid_exp, :kt128_sha256_p256, :kt128_sha256_ed25519]

  defp fixtures, do: V.keytrans_fixtures()

  test "suite_id/1 maps atoms to the §15.1 identifiers" do
    assert Keytrans.suite_id(:kt128_sha256_p256) == 0x0001
    assert Keytrans.suite_id(:kt128_sha256_ed25519) == 0x0002
    assert Keytrans.suite_id(:metamorphic_hybrid_exp) == 0xF000

    # Each fixture's declared suite_id agrees with the ergonomic API.
    for suite <- @suites do
      assert Keytrans.suite_id(suite) == fixtures().suites[suite].suite_id
    end
  end

  for suite <- @suites do
    describe "suite #{suite}" do
      @describetag suite: suite

      test "greatest-version search verifies the present value", %{suite: suite} do
        f = fixtures()
        s = f.suites[suite]

        assert {:ok, {:present, value_b64}} =
                 Keytrans.verify_search(
                   suite,
                   f.context,
                   s.vrf_public_b64,
                   s.root_b64,
                   f.label_b64,
                   s.search_proof_b64
                 )

        assert Base.decode64!(value_b64) == s.search_value
      end

      test "greatest-version search verifies an absent label", %{suite: suite} do
        f = fixtures()
        s = f.suites[suite]

        assert {:ok, :absent} =
                 Keytrans.verify_search(
                   suite,
                   f.context,
                   s.vrf_public_b64,
                   s.root_b64,
                   f.absent_label_b64,
                   s.absent_search_proof_b64
                 )
      end

      test "fixed-version search verifies the target version", %{suite: suite} do
        f = fixtures()
        s = f.suites[suite]

        assert {:ok, {:present, value_b64}} =
                 Keytrans.verify_fixed_version(
                   suite,
                   f.context,
                   s.vrf_public_b64,
                   s.root_b64,
                   f.label_b64,
                   s.fixed_version_proof_b64
                 )

        assert Base.decode64!(value_b64) == s.fixed_version_value
      end

      test "monitor proof verifies a known version", %{suite: suite} do
        f = fixtures()
        s = f.suites[suite]

        assert {:ok, true} =
                 Keytrans.verify_monitor(
                   suite,
                   f.context,
                   s.vrf_public_b64,
                   s.root_b64,
                   f.label_b64,
                   s.monitor_proof_b64
                 )
      end

      test "a tampered root is rejected", %{suite: suite} do
        f = fixtures()
        s = f.suites[suite]
        bad_root = flip_first_byte(s.root_b64)

        assert {:error, _} =
                 Keytrans.verify_search(
                   suite,
                   f.context,
                   s.vrf_public_b64,
                   bad_root,
                   f.label_b64,
                   s.search_proof_b64
                 )
      end

      test "the wrong suite is rejected", %{suite: suite} do
        f = fixtures()
        s = f.suites[suite]
        wrong = Enum.find(@suites, &(&1 != suite))

        assert {:error, _} =
                 Keytrans.verify_search(
                   wrong,
                   f.context,
                   s.vrf_public_b64,
                   s.root_b64,
                   f.label_b64,
                   s.search_proof_b64
                 )
      end
    end
  end

  defp flip_first_byte(b64) do
    <<first, rest::binary>> = Base.decode64!(b64)
    Base.encode64(<<Bitwise.bxor(first, 1), rest::binary>>)
  end
end
