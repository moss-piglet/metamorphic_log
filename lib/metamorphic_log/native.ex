defmodule MetamorphicLog.Native do
  @moduledoc false
  # Low-level NIF bindings. Use the public API modules instead.

  version = Mix.Project.config()[:version]

  use RustlerPrecompiled,
    otp_app: :metamorphic_log,
    crate: "metamorphic_log_nif",
    base_url: "https://github.com/moss-piglet/metamorphic_log/releases/download/v#{version}",
    force_build: System.get_env("METAMORPHIC_LOG_BUILD") in ["1", "true"],
    version: version,
    nif_versions: ["2.15", "2.16", "2.17"],
    targets: [
      "aarch64-apple-darwin",
      "x86_64-apple-darwin",
      "x86_64-unknown-linux-gnu",
      "aarch64-unknown-linux-gnu",
      "x86_64-pc-windows-msvc"
    ]

  # Inclusion / consistency proofs
  def nif_verify_inclusion(_index, _size, _leaf_hash_b64, _proof_b64, _root_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_verify_consistency(_size1, _size2, _proof_b64, _root1_b64, _root2_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  # Canonical leaf (mosslet/key-history/v1)
  def nif_key_history_v1_canonical_bytes(
        _seq,
        _ts_ms,
        _enc_x25519_b64,
        _enc_pq_b64,
        _signing_pub_b64,
        _prev_entry_hash_b64
      ),
      do: :erlang.nif_error(:nif_not_loaded)

  def nif_key_history_v1_entry_hash(
        _seq,
        _ts_ms,
        _enc_x25519_b64,
        _enc_pq_b64,
        _signing_pub_b64,
        _prev_entry_hash_b64
      ),
      do: :erlang.nif_error(:nif_not_loaded)

  def nif_key_history_v1_rfc6962_leaf_hash(
        _seq,
        _ts_ms,
        _enc_x25519_b64,
        _enc_pq_b64,
        _signing_pub_b64,
        _prev_entry_hash_b64
      ),
      do: :erlang.nif_error(:nif_not_loaded)

  # Signed notes / checkpoints
  def nif_verify_signed_note(_note_text, _vkeys), do: :erlang.nif_error(:nif_not_loaded)
  def nif_checkpoint_verify(_note_text, _vkeys), do: :erlang.nif_error(:nif_not_loaded)
  def nif_checkpoint_parse(_body_text), do: :erlang.nif_error(:nif_not_loaded)

  def nif_checkpoint_verify_inclusion(
        _note_text,
        _vkeys,
        _leaf_index,
        _leaf_hash_b64,
        _proof_b64
      ),
      do: :erlang.nif_error(:nif_not_loaded)

  def nif_checkpoint_verify_consistency(_older_note, _newer_note, _vkeys, _proof_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  # Signing / encoding (producer helpers)
  def nif_vkey_encode_hybrid(_name, _public_key_b64), do: :erlang.nif_error(:nif_not_loaded)
  def nif_vkey_encode_ed25519(_name, _public_key_b64), do: :erlang.nif_error(:nif_not_loaded)
  def nif_note_sign_hybrid(_text, _name, _secret_key_b64), do: :erlang.nif_error(:nif_not_loaded)
  def nif_note_sign_ed25519(_text, _name, _seed_b64), do: :erlang.nif_error(:nif_not_loaded)

  def nif_checkpoint_sign_hybrid(_origin, _size, _root_b64, _name, _secret_key_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  # CONIKS
  def nif_coniks_verify_lookup(
        _namespace,
        _vrf_public_b64,
        _root_b64,
        _identity_b64,
        _proof_b64
      ),
      do: :erlang.nif_error(:nif_not_loaded)

  def nif_coniks_verify_absence(
        _namespace,
        _vrf_public_b64,
        _root_b64,
        _identity_b64,
        _proof_b64
      ),
      do: :erlang.nif_error(:nif_not_loaded)

  # Commitments
  def nif_verify_commitment(_context, _commitment_b64, _value_b64, _opening_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  # Namespace policy
  def nif_signed_policy_verify(_signed_b64), do: :erlang.nif_error(:nif_not_loaded)

  # Arity mirrors the Rust `#[rustler::nif]` FFI boundary one-to-one; the
  # ergonomic public surface is `MetamorphicLog.Policy.sign/2`, which takes a
  # keyword list. Grouping these into a struct would only move the fan-out into
  # a NIF decoder without improving the caller, so the arity check is waived for
  # this private, `@moduledoc false` binding stub.
  # credo:disable-for-next-line Credo.Check.Refactor.FunctionArity
  def nif_signed_policy_sign(
        _namespace,
        _policy_schema_version,
        _security_level,
        _checkpoint_suite,
        _commitment_hash,
        _vrf_mode,
        _directory_mode,
        _keytrans_suite,
        _effective_from,
        _created_at,
        _prev_policy_hash_b64,
        _secret_key_b64
      ),
      do: :erlang.nif_error(:nif_not_loaded)

  def nif_policy_enforce_checkpoint_signing_key(_signed_b64, _public_key_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_policy_enforce_checkpoint_signature(_signed_b64, _signature_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_policy_enforce_vrf_suite_id(_signed_b64, _observed_suite_id),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_policy_enforce_commitment_hash(_signed_b64, _observed),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_policy_enforce_directory_backend(_signed_b64, _observed_backend_id),
    do: :erlang.nif_error(:nif_not_loaded)

  # KEYTRANS (combined-tree directory) verification — Slice 9
  def nif_keytrans_verify_search(
        _suite_id,
        _context,
        _vrf_public_b64,
        _root_b64,
        _label_b64,
        _proof_b64
      ),
      do: :erlang.nif_error(:nif_not_loaded)

  def nif_keytrans_verify_fixed_version(
        _suite_id,
        _context,
        _vrf_public_b64,
        _root_b64,
        _label_b64,
        _proof_b64
      ),
      do: :erlang.nif_error(:nif_not_loaded)

  def nif_keytrans_verify_monitor(
        _suite_id,
        _context,
        _vrf_public_b64,
        _root_b64,
        _label_b64,
        _proof_b64
      ),
      do: :erlang.nif_error(:nif_not_loaded)

  # Ingestion primitives
  def nif_dedup_key_from_record(_namespace, _payload_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_dedup_key_from_token(_namespace, _token_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_tiles_to_flush(_old_size, _new_size), do: :erlang.nif_error(:nif_not_loaded)
  def nif_entry_bundles_to_flush(_old_size, _new_size), do: :erlang.nif_error(:nif_not_loaded)
  def nif_tiles_for_size(_size), do: :erlang.nif_error(:nif_not_loaded)
  def nif_partial_width(_level, _size), do: :erlang.nif_error(:nif_not_loaded)

  def nif_tile_hashes(_level, _index, _width, _bytes_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_recompute_root(_leaf_hashes_b64), do: :erlang.nif_error(:nif_not_loaded)
  def nif_parent_hash(_tile_hashes_b64), do: :erlang.nif_error(:nif_not_loaded)

  # Anchoring (Slice 8)
  def nif_anchor_record_canonical_bytes(
        _origin,
        _size,
        _root_b64,
        _commitment_alg,
        _medium,
        _locator_b64
      ),
      do: :erlang.nif_error(:nif_not_loaded)

  def nif_anchor_record_parse(_record_b64), do: :erlang.nif_error(:nif_not_loaded)
  def nif_anchor_commitment(_record_b64), do: :erlang.nif_error(:nif_not_loaded)
  def nif_anchor_record_rfc6962_leaf_hash(_record_b64), do: :erlang.nif_error(:nif_not_loaded)

  def nif_verify_anchored(_note_text, _vkeys, _record_b64, _prev_note, _consistency_proof_b64),
    do: :erlang.nif_error(:nif_not_loaded)
end
