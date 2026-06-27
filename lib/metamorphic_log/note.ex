defmodule MetamorphicLog.Note do
  @moduledoc """
  C2SP signed-note verification.

  A signed note is a UTF-8 text body followed by one or more signature lines, as
  defined by the [C2SP signed-note](https://github.com/C2SP/C2SP/blob/main/signed-note.md)
  spec. This engine supports two signature types:

    * **Ed25519** — the classical C2SP signature type.
    * **Metamorphic hybrid** — an additive composite (`ML-DSA` + `Ed25519`,
      strict-AND verify) that wedges post-quantum integrity into the same note
      format. ML-DSA signing is hedged/randomized, so signature *bytes* are not
      reproducible, but verification is fully deterministic.

  `verify/2` takes the note text and a list of **trusted verifier keys** (the
  C2SP `name+hash+base64key` encoding). Unknown-key signatures are ignored; a
  signature from a *known* key that fails rejects the whole note.
  """

  alias MetamorphicLog.Native

  @doc """
  Verify `note_text` against `trusted_vkeys`.

  Returns `{:ok, verified_count}` — the number of trusted signatures that
  verified (always ≥ 1 on success) — or `{:error, reason}` (including
  `"no trusted signature"` when none of the trusted keys signed).

  ## Example

      {:ok, 1} = MetamorphicLog.Note.verify(note_text, [vkey])

  """
  @spec verify(note_text :: String.t(), trusted_vkeys :: [String.t()]) ::
          {:ok, non_neg_integer()} | {:error, String.t()}
  def verify(note_text, trusted_vkeys)
      when is_binary(note_text) and is_list(trusted_vkeys) do
    Native.nif_verify_signed_note(note_text, trusted_vkeys)
  end

  @doc """
  Boolean form of `verify/2`. Returns `true` if at least one trusted key signed
  and verified.
  """
  @spec verified?(String.t(), [String.t()]) :: boolean()
  def verified?(note_text, trusted_vkeys) do
    match?({:ok, _}, verify(note_text, trusted_vkeys))
  end
end
