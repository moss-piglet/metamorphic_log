defmodule MetamorphicLog.Commitment do
  @moduledoc """
  SHA3-512 commitment verification (CONIKS value commitments).

  A commitment is `SHA3-512_with_context(context, opening(32 bytes) || value)`.
  Given the public `context` label, the 64-byte `commitment`, the committed
  `value`, and the 32-byte `opening`, `verify/4` recomputes and constant-time
  compares.

  All binary arguments are **base64-encoded**.
  """

  alias MetamorphicLog.Native

  @doc """
  Verify that `commitment` opens to `value` under `opening` and `context`.

  Returns `:ok` or `{:error, reason}`.

  ## Example

      :ok = MetamorphicLog.Commitment.verify(context, commitment, value, opening)

  """
  @spec verify(
          context :: String.t(),
          commitment_b64 :: String.t(),
          value_b64 :: String.t(),
          opening_b64 :: String.t()
        ) :: :ok | {:error, String.t()}
  def verify(context, commitment_b64, value_b64, opening_b64)
      when is_binary(context) and is_binary(commitment_b64) and is_binary(value_b64) and
             is_binary(opening_b64) do
    Native.nif_verify_commitment(context, commitment_b64, value_b64, opening_b64)
  end

  @doc "Boolean form of `verify/4`. Returns `true` only on a valid opening."
  @spec valid?(String.t(), String.t(), String.t(), String.t()) :: boolean()
  def valid?(context, commitment_b64, value_b64, opening_b64) do
    verify(context, commitment_b64, value_b64, opening_b64) == :ok
  end
end
