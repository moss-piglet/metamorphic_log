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
