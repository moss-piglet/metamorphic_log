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

  def nif_policy_enforce_checkpoint_signing_key(_signed_b64, _public_key_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_policy_enforce_checkpoint_signature(_signed_b64, _signature_b64),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_policy_enforce_vrf_suite_id(_signed_b64, _observed_suite_id),
    do: :erlang.nif_error(:nif_not_loaded)

  def nif_policy_enforce_commitment_hash(_signed_b64, _observed),
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
end
