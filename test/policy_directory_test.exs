defmodule MetamorphicLog.PolicyDirectoryTest do
  @moduledoc """
  The Slice 9 directory axis on `MetamorphicLog.Policy`: the additive
  `:directory_mode` / `:keytrans_suite` fields on a verified policy, and
  `enforce_directory_backend/2` (declared == observed for the backend).

  The frozen CONIKS-route policy KAT is byte-for-byte unchanged; the new fields
  are additive and default to the CONIKS route.
  """
  use ExUnit.Case, async: true

  alias MetamorphicLog.Policy
  alias MetamorphicLog.Vectors, as: V

  test "the frozen CONIKS policy declares the CONIKS directory route" do
    assert {:ok, policy} = Policy.verify(V.signed_policy_b64())
    assert policy.directory_mode == :coniks
    # Defaulted, additive field — meaningful only on the KEYTRANS route.
    assert policy.keytrans_suite == :metamorphic_hybrid_exp
    # Existing posture fields are unchanged.
    assert policy.commitment_hash in [:sha3_256, :sha3_512]
  end

  test "enforce_directory_backend accepts the declared (CONIKS) backend" do
    assert :ok = Policy.enforce_directory_backend(V.signed_policy_b64(), :coniks)
    # Raw u16 form (0x0001 == CONIKS_V1) is equivalent.
    assert :ok = Policy.enforce_directory_backend(V.signed_policy_b64(), 0x0001)
  end

  test "enforce_directory_backend rejects a mismatched backend" do
    assert {:error, _} = Policy.enforce_directory_backend(V.signed_policy_b64(), :keytrans)
    assert {:error, _} = Policy.enforce_directory_backend(V.signed_policy_b64(), 0xF004)
  end
end
