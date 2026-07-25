defmodule MetamorphicLog.SigningTest do
  @moduledoc """
  Producer ↔ verifier round-trips for the C2SP signing surface.

  These tests close the loop entirely inside the library: sign an artifact with
  a real metamorphic-crypto composite key (hybrid) or a raw Ed25519 seed
  (classical), derive the matching verifier key, and assert the existing
  verification path accepts it — then assert tamper and foreign-key rejection.

  ML-DSA signing is hedged (non-deterministic), so we lock the *round-trip*, not
  the signature bytes.
  """

  use ExUnit.Case, async: true

  alias MetamorphicLog.{Checkpoint, Note, Policy, VerifierKey}

  @origin "metamorphic.app/signing-test"
  @name @origin
  # A namespace label is printable ASCII without '/' (a stricter grammar than a
  # checkpoint origin / verifier-key name, which do allow '/').
  @namespace "metamorphic.app-signing-test"

  describe "hybrid checkpoint round-trip" do
    setup do
      %{public_key: pk_b64, secret_key: sk_b64} =
        MetamorphicCrypto.Sign.generate_signing_keypair()

      {:ok, vkey} = VerifierKey.encode_hybrid(@name, pk_b64)
      size = 42
      root_b64 = Base.encode64(:crypto.strong_rand_bytes(32))

      {:ok, note} = Checkpoint.sign_hybrid(@origin, size, root_b64, @name, sk_b64)

      %{sk: sk_b64, pk: pk_b64, vkey: vkey, note: note, size: size, root_b64: root_b64}
    end

    test "the derived verifier key accepts the signed checkpoint and returns the head",
         %{vkey: vkey, note: note, size: size, root_b64: root_b64} do
      assert {:ok, %Checkpoint{origin: @origin, size: ^size, root: ^root_b64}} =
               Checkpoint.verify(note, [vkey])
    end

    test "a tampered checkpoint body is rejected", %{vkey: vkey, note: note} do
      # Flip the size line in the body; the signature no longer covers it.
      tampered = String.replace(note, "\n42\n", "\n43\n", global: false)
      refute tampered == note
      assert {:error, _reason} = Checkpoint.verify(tampered, [vkey])
    end

    test "a foreign key (same bytes, wrong name) is rejected", %{pk: pk_b64, note: note} do
      {:ok, foreign_vkey} = VerifierKey.encode_hybrid("metamorphic.app/someone-else", pk_b64)
      assert {:error, _reason} = Checkpoint.verify(note, [foreign_vkey])
    end

    test "signing twice produces different bytes but both verify (hedged ML-DSA)",
         %{sk: sk_b64, vkey: vkey, size: size, root_b64: root_b64} do
      {:ok, note_a} = Checkpoint.sign_hybrid(@origin, size, root_b64, @name, sk_b64)
      {:ok, note_b} = Checkpoint.sign_hybrid(@origin, size, root_b64, @name, sk_b64)

      refute note_a == note_b
      assert {:ok, %Checkpoint{}} = Checkpoint.verify(note_a, [vkey])
      assert {:ok, %Checkpoint{}} = Checkpoint.verify(note_b, [vkey])
    end
  end

  describe "ed25519 note round-trip" do
    setup do
      # The Ed25519 seed IS the 32-byte private scalar; derive the matching
      # public key with Erlang's crypto (metamorphic-crypto only ships the
      # hybrid composite suites).
      seed = :crypto.strong_rand_bytes(32)
      {public_key, ^seed} = :crypto.generate_key(:eddsa, :ed25519, seed)

      {:ok, vkey} = VerifierKey.encode_ed25519(@name, Base.encode64(public_key))
      body = "#{@origin}\n7\n#{Base.encode64(:crypto.strong_rand_bytes(32))}\n"
      {:ok, note} = Note.sign_ed25519(body, @name, Base.encode64(seed))

      %{vkey: vkey, note: note, body: body}
    end

    test "the derived verifier key accepts the signed note", %{vkey: vkey, note: note} do
      assert {:ok, _} = Note.verify(note, [vkey])
    end

    test "a tampered note body is rejected", %{vkey: vkey, note: note} do
      tampered = String.replace(note, "\n7\n", "\n8\n", global: false)
      refute tampered == note
      assert {:error, _reason} = Note.verify(tampered, [vkey])
    end
  end

  describe "dual-line checkpoint round-trip" do
    setup do
      %{public_key: pk_b64, secret_key: sk_b64} =
        MetamorphicCrypto.Sign.generate_signing_keypair()

      {:ok, hybrid_vkey} = VerifierKey.encode_hybrid(@name, pk_b64)
      {:ok, ed25519_vkey} = VerifierKey.encode_ed25519_from_hybrid(@name, pk_b64)

      size = 42
      root_b64 = Base.encode64(:crypto.strong_rand_bytes(32))
      {:ok, note} = Checkpoint.sign_dual(@origin, size, root_b64, @name, sk_b64)

      %{
        sk: sk_b64,
        pk: pk_b64,
        hybrid_vkey: hybrid_vkey,
        ed25519_vkey: ed25519_vkey,
        note: note,
        size: size,
        root_b64: root_b64
      }
    end

    test "each line verifies independently against its own vkey",
         %{hybrid_vkey: hybrid_vkey, ed25519_vkey: ed25519_vkey, note: note} do
      # A PQ-aware verifier accepts the hybrid line (ignoring the 0x01 line);
      # a stock Ed25519-only witness accepts the 0x01 line (ignoring the
      # hybrid line); both together verify both lines.
      assert {:ok, 1} = Note.verify(note, [hybrid_vkey])
      assert {:ok, 1} = Note.verify(note, [ed25519_vkey])
      assert {:ok, 2} = Note.verify(note, [hybrid_vkey, ed25519_vkey])
    end

    test "the two lines share the key name but carry distinct key ids",
         %{hybrid_vkey: hybrid_vkey, ed25519_vkey: ed25519_vkey, note: note} do
      [_body, sig_block] = String.split(note, "\n\n", parts: 2)
      lines = String.split(sig_block, "\n", trim: true)
      assert [_, _] = lines

      key_ids =
        for line <- lines do
          assert String.starts_with?(line, "— #{@name} ")
          ["—", _name, blob] = String.split(line, " ", parts: 3)
          <<key_id::32-big, _sig::binary>> = Base.decode64!(blob)
          key_id
        end

      assert Enum.uniq(key_ids) == key_ids

      # ...and each key id is the one embedded in the matching vkey.
      assert [hybrid_id, ed25519_id] = key_ids
      assert vkey_key_id(hybrid_vkey) == hybrid_id
      assert vkey_key_id(ed25519_vkey) == ed25519_id
    end

    test "the derived 0x01 vkey is deterministic", %{pk: pk_b64, ed25519_vkey: ed25519_vkey} do
      assert {:ok, ^ed25519_vkey} = VerifierKey.encode_ed25519_from_hybrid(@name, pk_b64)
    end

    test "a tampered checkpoint body is rejected by both verifier classes",
         %{hybrid_vkey: hybrid_vkey, ed25519_vkey: ed25519_vkey, note: note} do
      tampered = String.replace(note, "\n42\n", "\n43\n", global: false)
      refute tampered == note
      assert {:error, _reason} = Note.verify(tampered, [hybrid_vkey])
      assert {:error, _reason} = Note.verify(tampered, [ed25519_vkey])
    end

    test "the checkpoint parses back out of the dual note",
         %{ed25519_vkey: ed25519_vkey, note: note, size: size, root_b64: root_b64} do
      assert {:ok, %Checkpoint{origin: @origin, size: ^size, root: ^root_b64}} =
               Checkpoint.verify(note, [ed25519_vkey])
    end

    test "suites without an Ed25519 classical half are rejected" do
      for suite <- [:hybrid_matched, :pure_cnsa2] do
        {:ok, kp} = MetamorphicCrypto.Sign.generate_signing_keypair_suite(suite, :cat5)
        root_b64 = Base.encode64(:crypto.strong_rand_bytes(32))

        assert {:error, _reason} =
                 Checkpoint.sign_dual(@origin, 1, root_b64, @name, kp.secret_key)

        assert {:error, _reason} = VerifierKey.encode_ed25519_from_hybrid(@name, kp.public_key)
      end
    end
  end

  describe "witness cosignature round-trip (0x04 Ed25519)" do
    setup do
      # The log dual-signs its checkpoint; the witness then cosigns the SAME
      # body (everything before the signature block, plus one trailing
      # newline).
      %{public_key: log_pk, secret_key: log_sk} =
        MetamorphicCrypto.Sign.generate_signing_keypair()

      {:ok, log_vkey} = VerifierKey.encode_hybrid(@name, log_pk)
      {:ok, log_ed25519_vkey} = VerifierKey.encode_ed25519_from_hybrid(@name, log_pk)
      root_b64 = Base.encode64(:crypto.strong_rand_bytes(32))
      {:ok, note} = Checkpoint.sign_dual(@origin, 42, root_b64, @name, log_sk)
      [body, _sig_block] = String.split(note, "\n\n", parts: 2)
      body = body <> "\n"

      # The witness's classical cosignature key (OTP eddsa derives the pubkey).
      witness = "witness.example.com/cosigner"
      seed = :crypto.strong_rand_bytes(32)
      {witness_pk, ^seed} = :crypto.generate_key(:eddsa, :ed25519, seed)

      {:ok, witness_vkey} =
        VerifierKey.encode_cosignature_ed25519(witness, Base.encode64(witness_pk))

      timestamp = System.system_time(:second)
      {:ok, line} = Note.sign_cosignature_ed25519(body, witness, Base.encode64(seed), timestamp)
      merged = note <> line <> "\n"

      %{
        log_vkey: log_vkey,
        log_ed25519_vkey: log_ed25519_vkey,
        witness_vkey: witness_vkey,
        note: note,
        merged: merged,
        cosig_line: line,
        witness: witness
      }
    end

    test "the merged note verifies for the log and the witness", %{
      log_vkey: log_vkey,
      log_ed25519_vkey: log_ed25519_vkey,
      witness_vkey: witness_vkey,
      merged: merged
    } do
      assert {:ok, 1} = Note.verify(merged, [witness_vkey])
      assert {:ok, 1} = Note.verify(merged, [log_vkey])
      # The witness vkey trusts no log line and the log hybrid vkey trusts no
      # cosignature, so each pair counts exactly its own lines.
      assert {:ok, 2} = Note.verify(merged, [log_vkey, witness_vkey])
      assert {:ok, 3} = Note.verify(merged, [log_vkey, log_ed25519_vkey, witness_vkey])
    end

    test "the cosignature line carries the witness vkey's key id", %{
      witness_vkey: witness_vkey,
      cosig_line: line,
      witness: witness
    } do
      assert String.starts_with?(line, "— #{witness} ")
      ["—", _name, blob] = String.split(line, " ", parts: 3)
      <<key_id::32-big, _sig::binary>> = Base.decode64!(blob)
      assert key_id == vkey_key_id(witness_vkey)
    end

    test "a tampered body rejects the cosignature", %{witness_vkey: witness_vkey, merged: merged} do
      tampered = String.replace(merged, "\n42\n", "\n43\n", global: false)
      assert {:error, _reason} = Note.verify(tampered, [witness_vkey])
    end
  end

  describe "witness cosignature round-trip (0x06 ML-DSA-44)" do
    setup do
      %{public_key: log_pk, secret_key: log_sk} =
        MetamorphicCrypto.Sign.generate_signing_keypair()

      {:ok, log_vkey} = VerifierKey.encode_hybrid(@name, log_pk)
      {:ok, log_ed25519_vkey} = VerifierKey.encode_ed25519_from_hybrid(@name, log_pk)
      root_b64 = Base.encode64(:crypto.strong_rand_bytes(32))
      {:ok, note} = Checkpoint.sign_dual(@origin, 42, root_b64, @name, log_sk)
      [body, _sig_block] = String.split(note, "\n\n", parts: 2)
      body = body <> "\n"

      # A Cat-2 hybrid keypair's ML-DSA half IS a raw ML-DSA-44 keypair:
      # secret `tag || ed25519_seed(32) || ml_dsa_seed(32)`, public
      # `tag || ed25519_pk(32) || ml_dsa_pk(1312)`. Extract both halves for the
      # witness's PQ cosignature key.
      {:ok, kp} = MetamorphicCrypto.Sign.generate_signing_keypair_suite(:hybrid, :cat2)
      sk_bytes = Base.decode64!(kp.secret_key)
      pk_bytes = Base.decode64!(kp.public_key)
      ml_seed = binary_part(sk_bytes, 33, 32)
      ml_pk = binary_part(pk_bytes, 33, 1312)

      witness = "witness.example.com/pq-cosigner"
      {:ok, witness_vkey} = VerifierKey.encode_cosignature_mldsa44(witness, Base.encode64(ml_pk))

      timestamp = System.system_time(:second)

      {:ok, line} =
        Note.sign_cosignature_mldsa44(body, witness, Base.encode64(ml_seed), timestamp)

      merged = note <> line <> "\n"

      %{
        log_vkey: log_vkey,
        log_ed25519_vkey: log_ed25519_vkey,
        witness_vkey: witness_vkey,
        merged: merged,
        cosig_line: line
      }
    end

    test "the merged note verifies for the log and the PQ witness", %{
      log_vkey: log_vkey,
      log_ed25519_vkey: log_ed25519_vkey,
      witness_vkey: witness_vkey,
      merged: merged
    } do
      assert {:ok, 1} = Note.verify(merged, [witness_vkey])
      assert {:ok, 2} = Note.verify(merged, [log_vkey, witness_vkey])
      assert {:ok, 3} = Note.verify(merged, [log_vkey, log_ed25519_vkey, witness_vkey])
    end

    test "a tampered body rejects the PQ cosignature", %{
      witness_vkey: witness_vkey,
      merged: merged
    } do
      tampered = String.replace(merged, "\n42\n", "\n43\n", global: false)
      assert {:error, _reason} = Note.verify(tampered, [witness_vkey])
    end
  end

  # `<name>+<hex key id>+<base64(type || key)>` — the middle segment.
  defp vkey_key_id(vkey) do
    [_name, hex_id, _key] = String.split(vkey, "+", parts: 3)
    <<key_id::32-big>> = Base.decode16!(hex_id, case: :lower)
    key_id
  end

  describe "policy round-trip" do
    test "a signed CONIKS policy verifies and reports the declared posture" do
      %{public_key: pk_b64, secret_key: sk_b64} =
        MetamorphicCrypto.Sign.generate_signing_keypair()

      params = [
        namespace: @namespace,
        policy_schema_version: 1,
        security_level: :cat3,
        checkpoint_suite: :hybrid,
        commitment_hash: :sha3_256,
        vrf_mode: :classical,
        directory_mode: :coniks,
        effective_from: 0,
        created_at: 0
      ]

      assert {:ok, signed} = Policy.sign(params, sk_b64)

      assert {:ok,
              %Policy{
                namespace: @namespace,
                security_level: :cat3,
                checkpoint_suite: :hybrid,
                commitment_hash: :sha3_256,
                vrf_mode: :classical,
                directory_mode: :coniks
              }} = Policy.verify(signed)

      # The declared checkpoint signing key is enforceable against the signer.
      assert :ok = Policy.enforce_checkpoint_signing_key(signed, pk_b64)
    end

    test "an unknown enum value is rejected before touching the NIF" do
      %{secret_key: sk_b64} = MetamorphicCrypto.Sign.generate_signing_keypair()

      params = [
        namespace: @namespace,
        policy_schema_version: 1,
        security_level: :cat9,
        checkpoint_suite: :hybrid,
        commitment_hash: :sha3_256,
        vrf_mode: :classical,
        directory_mode: :coniks,
        effective_from: 0,
        created_at: 0
      ]

      assert {:error, reason} = Policy.sign(params, sk_b64)
      assert reason =~ "security_level"
    end
  end
end
