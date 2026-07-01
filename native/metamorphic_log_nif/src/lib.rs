//! Rustler NIF bindings for `metamorphic-log`.
//!
//! Thin glue over the published `metamorphic-log` transparency-log engine. All
//! logic lives in the audited Rust core (single source of truth =
//! `metamorphic-crypto` + `metamorphic-log`); this layer only marshals values
//! across the BEAM boundary.
//!
//! ## Wire format
//!
//! Binary values cross the boundary **base64-encoded** (standard padded
//! alphabet), reusing `metamorphic_crypto::b64` — the same encoder used by the
//! engine and the browser WASM SDK — so a digest or canonical encoding produced
//! here is byte-identical to the WASM and native outputs. Text values
//! (checkpoint/note bodies, verifier keys, namespace labels) cross as UTF-8.
//!
//! ## Return shapes
//!
//! - Verification / enforcement predicates return `:ok` on success or
//!   `{:error, reason}` (a binary message) on failure — covering both a failed
//!   check and malformed input, faithful to the engine's `Result<()>`.
//! - Constructors / accessors that yield a value return `{:ok, value}` or
//!   `{:error, reason}`.
//! - Genuinely infallible helpers return the value directly.
//!
//! ## Scheduling
//!
//! CPU-bound work — proof verification, CONIKS VRF verification, signed-note /
//! policy signature verification (Ed25519 + ML-DSA), and Merkle recomputation —
//! runs on dirty CPU schedulers (`schedule = "DirtyCpu"`), per the project's
//! non-negotiable. Genuine micro-ops (canonical framing, single-hash leaf /
//! dedup digests, parsing, flush geometry) stay on normal schedulers.
#![forbid(unsafe_code)]

use metamorphic_crypto::b64;
use metamorphic_log::{
    anchor::{self, AnchorCommitment, AnchorLink, AnchorRecord, Medium},
    checkpoint::Checkpoint,
    commitment::{self, Commitment, Opening},
    coniks::{self, AbsenceProof, LookupProof, Namespace},
    directory::{DirectoryBackendId, SearchOutcome},
    ingest::{self, DedupKey},
    keytrans::{KeytransVerifier, KtSuite},
    leaf::key_history_v1,
    note::{SignedNote, VerifierKey},
    policy::{
        CheckpointSuite, CommitmentHash, DirectoryMode, KeytransSuite, SecurityLevel, SignedPolicy,
        VrfMode,
    },
    tile::{self, Tile},
    verify_consistency, verify_inclusion,
    vrf::{Ecvrf, VrfPublicKey},
};
use rustler::{Encoder, Env, Term};

mod atoms {
    rustler::atoms! { ok, error, present, absent }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// `:ok`
fn ok<'a>(env: Env<'a>) -> Term<'a> {
    atoms::ok().encode(env)
}

/// `{:ok, value}`
fn ok_val<'a>(env: Env<'a>, value: impl Encoder) -> Term<'a> {
    (atoms::ok(), value).encode(env)
}

/// `{:error, "reason"}`
fn err<'a>(env: Env<'a>, reason: impl ToString) -> Term<'a> {
    (atoms::error(), reason.to_string()).encode(env)
}

/// Decode a base64 string to bytes, or build an `{:error, _}` term.
macro_rules! decode {
    ($env:expr, $b64:expr) => {
        match b64::decode($b64) {
            Ok(bytes) => bytes,
            Err(e) => return err($env, e),
        }
    };
}

/// Decode a base64 string into a fixed-size array, or build an `{:error, _}`.
macro_rules! decode_array {
    ($env:expr, $b64:expr, $n:expr, $what:expr) => {{
        let bytes = decode!($env, $b64);
        match <[u8; $n]>::try_from(bytes.as_slice()) {
            Ok(arr) => arr,
            Err(_) => {
                return err(
                    $env,
                    format!("{} must be {} bytes, got {}", $what, $n, bytes.len()),
                );
            }
        }
    }};
}

/// Decode a list of base64 proof nodes into `Vec<Vec<u8>>`.
fn decode_proof<'a>(env: Env<'a>, proof_b64: &[String]) -> Result<Vec<Vec<u8>>, Term<'a>> {
    proof_b64
        .iter()
        .map(|node| b64::decode(node))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| err(env, e))
}

// ─── Inclusion / Consistency Proofs ──────────────────────────────────────────

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_verify_inclusion<'a>(
    env: Env<'a>,
    index: u64,
    size: u64,
    leaf_hash_b64: &str,
    proof_b64: Vec<String>,
    root_b64: &str,
) -> Term<'a> {
    let leaf_hash = decode!(env, leaf_hash_b64);
    let root = decode!(env, root_b64);
    let proof = match decode_proof(env, &proof_b64) {
        Ok(p) => p,
        Err(t) => return t,
    };
    match verify_inclusion(index, size, &leaf_hash, &proof, &root) {
        Ok(()) => ok(env),
        Err(e) => err(env, e),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_verify_consistency<'a>(
    env: Env<'a>,
    size1: u64,
    size2: u64,
    proof_b64: Vec<String>,
    root1_b64: &str,
    root2_b64: &str,
) -> Term<'a> {
    let root1 = decode!(env, root1_b64);
    let root2 = decode!(env, root2_b64);
    let proof = match decode_proof(env, &proof_b64) {
        Ok(p) => p,
        Err(t) => return t,
    };
    match verify_consistency(size1, size2, &proof, &root1, &root2) {
        Ok(()) => ok(env),
        Err(e) => err(env, e),
    }
}

// ─── Canonical Leaf (mosslet/key-history/v1 conformance instance) ─────────────

fn build_key_history_entry<'a>(
    env: Env<'a>,
    seq: u64,
    ts_ms: u64,
    enc_x25519_b64: &str,
    enc_pq_b64: &str,
    signing_pub_b64: &str,
    prev_entry_hash_b64: Option<String>,
) -> Result<key_history_v1::Entry, Term<'a>> {
    let prev_entry_hash = match prev_entry_hash_b64 {
        Some(ref h) => Some(b64::decode(h).map_err(|e| err(env, e))?),
        None => None,
    };
    Ok(key_history_v1::Entry {
        seq,
        ts_ms,
        enc_x25519: b64::decode(enc_x25519_b64).map_err(|e| err(env, e))?,
        enc_pq: b64::decode(enc_pq_b64).map_err(|e| err(env, e))?,
        signing_pub: b64::decode(signing_pub_b64).map_err(|e| err(env, e))?,
        prev_entry_hash,
    })
}

#[rustler::nif]
fn nif_key_history_v1_canonical_bytes<'a>(
    env: Env<'a>,
    seq: u64,
    ts_ms: u64,
    enc_x25519_b64: &str,
    enc_pq_b64: &str,
    signing_pub_b64: &str,
    prev_entry_hash_b64: Option<String>,
) -> Term<'a> {
    let entry = match build_key_history_entry(
        env,
        seq,
        ts_ms,
        enc_x25519_b64,
        enc_pq_b64,
        signing_pub_b64,
        prev_entry_hash_b64,
    ) {
        Ok(e) => e,
        Err(t) => return t,
    };
    match entry.canonical_bytes() {
        Ok(bytes) => ok_val(env, b64::encode(&bytes)),
        Err(e) => err(env, e),
    }
}

#[rustler::nif]
fn nif_key_history_v1_entry_hash<'a>(
    env: Env<'a>,
    seq: u64,
    ts_ms: u64,
    enc_x25519_b64: &str,
    enc_pq_b64: &str,
    signing_pub_b64: &str,
    prev_entry_hash_b64: Option<String>,
) -> Term<'a> {
    let entry = match build_key_history_entry(
        env,
        seq,
        ts_ms,
        enc_x25519_b64,
        enc_pq_b64,
        signing_pub_b64,
        prev_entry_hash_b64,
    ) {
        Ok(e) => e,
        Err(t) => return t,
    };
    match entry.entry_hash() {
        Ok(hash) => ok_val(env, b64::encode(&hash)),
        Err(e) => err(env, e),
    }
}

#[rustler::nif]
fn nif_key_history_v1_rfc6962_leaf_hash<'a>(
    env: Env<'a>,
    seq: u64,
    ts_ms: u64,
    enc_x25519_b64: &str,
    enc_pq_b64: &str,
    signing_pub_b64: &str,
    prev_entry_hash_b64: Option<String>,
) -> Term<'a> {
    let entry = match build_key_history_entry(
        env,
        seq,
        ts_ms,
        enc_x25519_b64,
        enc_pq_b64,
        signing_pub_b64,
        prev_entry_hash_b64,
    ) {
        Ok(e) => e,
        Err(t) => return t,
    };
    match entry.rfc6962_leaf_hash() {
        Ok(hash) => ok_val(env, b64::encode(&hash)),
        Err(e) => err(env, e),
    }
}

// ─── Signed Notes / Checkpoints (C2SP) ───────────────────────────────────────

fn parse_vkeys<'a>(env: Env<'a>, vkeys: &[String]) -> Result<Vec<VerifierKey>, Term<'a>> {
    vkeys
        .iter()
        .map(|v| VerifierKey::parse(v))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| err(env, e))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_verify_signed_note<'a>(env: Env<'a>, note_text: &str, vkeys: Vec<String>) -> Term<'a> {
    let trusted = match parse_vkeys(env, &vkeys) {
        Ok(t) => t,
        Err(t) => return t,
    };
    let note = match SignedNote::parse(note_text) {
        Ok(n) => n,
        Err(e) => return err(env, e),
    };
    match note.verify(&trusted) {
        Ok(verified) => ok_val(env, verified.len() as u32),
        Err(e) => err(env, e),
    }
}

/// `{origin, size, root_b64, [extensions]}`
fn checkpoint_tuple<'a>(env: Env<'a>, cp: &Checkpoint) -> Term<'a> {
    (
        cp.origin(),
        cp.size(),
        b64::encode(cp.root_hash()),
        cp.extensions().to_vec(),
    )
        .encode(env)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_checkpoint_verify<'a>(env: Env<'a>, note_text: &str, vkeys: Vec<String>) -> Term<'a> {
    let trusted = match parse_vkeys(env, &vkeys) {
        Ok(t) => t,
        Err(t) => return t,
    };
    match Checkpoint::from_signed_note(note_text, &trusted) {
        Ok(cp) => ok_val(env, checkpoint_tuple(env, &cp)),
        Err(e) => err(env, e),
    }
}

#[rustler::nif]
fn nif_checkpoint_parse<'a>(env: Env<'a>, body_text: &str) -> Term<'a> {
    match Checkpoint::parse(body_text) {
        Ok(cp) => ok_val(env, checkpoint_tuple(env, &cp)),
        Err(e) => err(env, e),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_checkpoint_verify_inclusion<'a>(
    env: Env<'a>,
    note_text: &str,
    vkeys: Vec<String>,
    leaf_index: u64,
    leaf_hash_b64: &str,
    proof_b64: Vec<String>,
) -> Term<'a> {
    let trusted = match parse_vkeys(env, &vkeys) {
        Ok(t) => t,
        Err(t) => return t,
    };
    let leaf_hash = decode!(env, leaf_hash_b64);
    let proof = match decode_proof(env, &proof_b64) {
        Ok(p) => p,
        Err(t) => return t,
    };
    let cp = match Checkpoint::from_signed_note(note_text, &trusted) {
        Ok(cp) => cp,
        Err(e) => return err(env, e),
    };
    match cp.verify_inclusion(leaf_index, &leaf_hash, &proof) {
        Ok(()) => ok(env),
        Err(e) => err(env, e),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_checkpoint_verify_consistency<'a>(
    env: Env<'a>,
    older_note: &str,
    newer_note: &str,
    vkeys: Vec<String>,
    proof_b64: Vec<String>,
) -> Term<'a> {
    let trusted = match parse_vkeys(env, &vkeys) {
        Ok(t) => t,
        Err(t) => return t,
    };
    let proof = match decode_proof(env, &proof_b64) {
        Ok(p) => p,
        Err(t) => return t,
    };
    let older = match Checkpoint::from_signed_note(older_note, &trusted) {
        Ok(cp) => cp,
        Err(e) => return err(env, e),
    };
    let newer = match Checkpoint::from_signed_note(newer_note, &trusted) {
        Ok(cp) => cp,
        Err(e) => return err(env, e),
    };
    match older.verify_consistency(&newer, &proof) {
        Ok(()) => ok(env),
        Err(e) => err(env, e),
    }
}

// ─── CONIKS (Key Transparency) ───────────────────────────────────────────────

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_coniks_verify_lookup<'a>(
    env: Env<'a>,
    namespace: &str,
    vrf_public_b64: &str,
    root_b64: &str,
    identity_b64: &str,
    proof_b64: &str,
) -> Term<'a> {
    let ns = match Namespace::parse(namespace) {
        Ok(n) => n,
        Err(e) => return err(env, e),
    };
    let vrf_public = VrfPublicKey::from_bytes(decode!(env, vrf_public_b64));
    let root = decode_array!(env, root_b64, 64, "CONIKS root");
    let identity = decode!(env, identity_b64);
    let proof_bytes = decode!(env, proof_b64);
    let proof = match LookupProof::from_bytes(&proof_bytes) {
        Ok(p) => p,
        Err(e) => return err(env, e),
    };
    match coniks::verify_lookup(&Ecvrf, &ns, &vrf_public, &root, &identity, &proof) {
        Ok(value) => ok_val(env, b64::encode(&value)),
        Err(e) => err(env, e),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_coniks_verify_absence<'a>(
    env: Env<'a>,
    namespace: &str,
    vrf_public_b64: &str,
    root_b64: &str,
    identity_b64: &str,
    proof_b64: &str,
) -> Term<'a> {
    let ns = match Namespace::parse(namespace) {
        Ok(n) => n,
        Err(e) => return err(env, e),
    };
    let vrf_public = VrfPublicKey::from_bytes(decode!(env, vrf_public_b64));
    let root = decode_array!(env, root_b64, 64, "CONIKS root");
    let identity = decode!(env, identity_b64);
    let proof_bytes = decode!(env, proof_b64);
    let proof = match AbsenceProof::from_bytes(&proof_bytes) {
        Ok(p) => p,
        Err(e) => return err(env, e),
    };
    match coniks::verify_absence(&Ecvrf, &ns, &vrf_public, &root, &identity, &proof) {
        Ok(()) => ok(env),
        Err(e) => err(env, e),
    }
}

// ─── Commitments (SHA3-512) ──────────────────────────────────────────────────

#[rustler::nif]
fn nif_verify_commitment<'a>(
    env: Env<'a>,
    context: &str,
    commitment_b64: &str,
    value_b64: &str,
    opening_b64: &str,
) -> Term<'a> {
    let commitment = Commitment::from_bytes(decode_array!(env, commitment_b64, 64, "commitment"));
    let opening = Opening::from_bytes(decode_array!(env, opening_b64, 32, "opening"));
    let value = decode!(env, value_b64);
    match commitment::verify_commitment(context, &commitment, &value, &opening) {
        Ok(()) => ok(env),
        Err(e) => err(env, e),
    }
}

// ─── Namespace Policy ────────────────────────────────────────────────────────

fn security_level_str(level: SecurityLevel) -> &'static str {
    match level {
        SecurityLevel::Cat3 => "cat3",
        SecurityLevel::Cat5 => "cat5",
    }
}

fn checkpoint_suite_str(suite: CheckpointSuite) -> &'static str {
    match suite {
        CheckpointSuite::Hybrid => "hybrid",
        CheckpointSuite::HybridMatched => "hybrid_matched",
        CheckpointSuite::PureCnsa2 => "pure_cnsa2",
    }
}

fn commitment_hash_str(hash: CommitmentHash) -> &'static str {
    match hash {
        CommitmentHash::Sha3_256 => "sha3_256",
        CommitmentHash::Sha3_512 => "sha3_512",
    }
}

fn commitment_hash_from_str(s: &str) -> Option<CommitmentHash> {
    match s {
        "sha3_256" => Some(CommitmentHash::Sha3_256),
        "sha3_512" => Some(CommitmentHash::Sha3_512),
        _ => None,
    }
}

fn vrf_mode_str(mode: VrfMode) -> &'static str {
    match mode {
        VrfMode::Classical => "classical",
        VrfMode::HybridOutput => "hybrid_output",
        VrfMode::PurePqExperimental => "pure_pq_experimental",
    }
}

fn directory_mode_str(mode: DirectoryMode) -> &'static str {
    match mode {
        DirectoryMode::Coniks => "coniks",
        DirectoryMode::Keytrans => "keytrans",
    }
}

fn keytrans_suite_str(suite: KeytransSuite) -> &'static str {
    match suite {
        KeytransSuite::MetamorphicHybridExp => "metamorphic_hybrid_exp",
        KeytransSuite::Kt128Sha256P256 => "kt128_sha256_p256",
        KeytransSuite::Kt128Sha256Ed25519 => "kt128_sha256_ed25519",
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_signed_policy_verify<'a>(env: Env<'a>, signed_b64: &str) -> Term<'a> {
    let bytes = decode!(env, signed_b64);
    let signed = match SignedPolicy::parse(&bytes) {
        Ok(s) => s,
        Err(e) => return err(env, e),
    };
    let policy = match signed.verify() {
        Ok(p) => p,
        Err(e) => return err(env, e),
    };
    let policy_hash = match policy.policy_hash() {
        Ok(h) => h,
        Err(e) => return err(env, e),
    };
    // Grouped into 5-tuples (Rustler tuples max at arity 7); the Elixir
    // wrapper reassembles these into a single policy map. The third group
    // carries the Slice 9 directory axis (additive; CONIKS-route output is
    // unchanged apart from these new, defaulted fields).
    let fields = (
        (
            policy.namespace().as_str().to_string(),
            policy.policy_schema_version(),
            security_level_str(policy.security_level()),
            checkpoint_suite_str(policy.checkpoint_suite()),
            commitment_hash_str(policy.commitment_hash()),
        ),
        (
            vrf_mode_str(policy.vrf_mode()),
            policy.effective_from(),
            policy.created_at(),
            b64::encode(&policy_hash),
            b64::encode(&policy.rfc6962_leaf_hash()),
        ),
        (
            directory_mode_str(policy.directory_mode()),
            keytrans_suite_str(policy.keytrans_suite()),
        ),
    );
    ok_val(env, fields)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_policy_enforce_checkpoint_signing_key<'a>(
    env: Env<'a>,
    signed_b64: &str,
    public_key_b64: &str,
) -> Term<'a> {
    let bytes = decode!(env, signed_b64);
    let signed = match SignedPolicy::parse(&bytes) {
        Ok(s) => s,
        Err(e) => return err(env, e),
    };
    let policy = match signed.verify() {
        Ok(p) => p,
        Err(e) => return err(env, e),
    };
    match policy.enforce_checkpoint_signing_key(public_key_b64) {
        Ok(()) => ok(env),
        Err(e) => err(env, e),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_policy_enforce_checkpoint_signature<'a>(
    env: Env<'a>,
    signed_b64: &str,
    signature_b64: &str,
) -> Term<'a> {
    let bytes = decode!(env, signed_b64);
    let signed = match SignedPolicy::parse(&bytes) {
        Ok(s) => s,
        Err(e) => return err(env, e),
    };
    let policy = match signed.verify() {
        Ok(p) => p,
        Err(e) => return err(env, e),
    };
    match policy.enforce_checkpoint_signature(signature_b64) {
        Ok(()) => ok(env),
        Err(e) => err(env, e),
    }
}

#[rustler::nif]
fn nif_policy_enforce_vrf_suite_id<'a>(
    env: Env<'a>,
    signed_b64: &str,
    observed_suite_id: u8,
) -> Term<'a> {
    let bytes = decode!(env, signed_b64);
    let signed = match SignedPolicy::parse(&bytes) {
        Ok(s) => s,
        Err(e) => return err(env, e),
    };
    let policy = match signed.verify() {
        Ok(p) => p,
        Err(e) => return err(env, e),
    };
    match policy.enforce_vrf_suite_id(observed_suite_id) {
        Ok(()) => ok(env),
        Err(e) => err(env, e),
    }
}

#[rustler::nif]
fn nif_policy_enforce_commitment_hash<'a>(
    env: Env<'a>,
    signed_b64: &str,
    observed: &str,
) -> Term<'a> {
    let observed_hash = match commitment_hash_from_str(observed) {
        Some(h) => h,
        None => return err(env, format!("unknown commitment hash: {observed}")),
    };
    let bytes = decode!(env, signed_b64);
    let signed = match SignedPolicy::parse(&bytes) {
        Ok(s) => s,
        Err(e) => return err(env, e),
    };
    let policy = match signed.verify() {
        Ok(p) => p,
        Err(e) => return err(env, e),
    };
    match policy.enforce_commitment_hash(observed_hash) {
        Ok(()) => ok(env),
        Err(e) => err(env, e),
    }
}

#[rustler::nif]
fn nif_policy_enforce_directory_backend<'a>(
    env: Env<'a>,
    signed_b64: &str,
    observed_backend_id: u16,
) -> Term<'a> {
    let bytes = decode!(env, signed_b64);
    let signed = match SignedPolicy::parse(&bytes) {
        Ok(s) => s,
        Err(e) => return err(env, e),
    };
    let policy = match signed.verify() {
        Ok(p) => p,
        Err(e) => return err(env, e),
    };
    match policy.enforce_directory_backend(DirectoryBackendId::from_u16(observed_backend_id)) {
        Ok(()) => ok(env),
        Err(e) => err(env, e),
    }
}

// ─── KEYTRANS (combined-tree directory) verification — Slice 9 ────────────────
//
// Suite-aware relying-party verification over the crate's byte-oriented
// `KeytransVerifier` APIs (the same movable `KEYTRANS_EXP_04` wire the WASM SDK
// verifies). The suite is always an explicit argument — the caller maps the
// §15.1 `suite_id` u16 to a `KtSuite` (`KtSuite::from_suite_id`), from which we
// take the matching VRF (`suite.vrf()`); nothing defaults to a hardcoded suite.
//
// `context` is the commitment domain-separation string, `vrf_public_b64` the
// operator's VRF public key, `root_b64` the published combined-tree root,
// `label_b64` the queried label, and `proof_b64` the movable proof blob.

/// `{:ok, {:present, value_b64}}` | `{:ok, :absent}` from a `SearchOutcome`.
fn search_outcome_term<'a>(env: Env<'a>, outcome: SearchOutcome) -> Term<'a> {
    match outcome {
        SearchOutcome::Present(value) => ok_val(env, (atoms::present(), b64::encode(&value))),
        SearchOutcome::Absent => ok_val(env, atoms::absent()),
    }
}

/// Build a suite-aware verifier from an explicit §15.1 suite id and public key.
fn keytrans_verifier<'a>(
    env: Env<'a>,
    suite_id: u16,
    context: &str,
    vrf_public_b64: &str,
) -> Result<KeytransVerifier, Term<'a>> {
    let suite = KtSuite::from_suite_id(suite_id).map_err(|e| err(env, e))?;
    let vrf_public =
        VrfPublicKey::from_bytes(b64::decode(vrf_public_b64).map_err(|e| err(env, e))?);
    Ok(KeytransVerifier::new_with_suite(
        context,
        suite,
        suite.vrf(),
        vrf_public,
    ))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_keytrans_verify_search<'a>(
    env: Env<'a>,
    suite_id: u16,
    context: &str,
    vrf_public_b64: &str,
    root_b64: &str,
    label_b64: &str,
    proof_b64: &str,
) -> Term<'a> {
    let verifier = match keytrans_verifier(env, suite_id, context, vrf_public_b64) {
        Ok(v) => v,
        Err(t) => return t,
    };
    let root = decode!(env, root_b64);
    let label = decode!(env, label_b64);
    let proof = decode!(env, proof_b64);
    match verifier.verify_search_bytes(&root, &label, &proof) {
        Ok(outcome) => search_outcome_term(env, outcome),
        Err(e) => err(env, e),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_keytrans_verify_fixed_version<'a>(
    env: Env<'a>,
    suite_id: u16,
    context: &str,
    vrf_public_b64: &str,
    root_b64: &str,
    label_b64: &str,
    proof_b64: &str,
) -> Term<'a> {
    let verifier = match keytrans_verifier(env, suite_id, context, vrf_public_b64) {
        Ok(v) => v,
        Err(t) => return t,
    };
    let root = decode!(env, root_b64);
    let label = decode!(env, label_b64);
    let proof = decode!(env, proof_b64);
    match verifier.verify_fixed_version_bytes(&root, &label, &proof) {
        Ok(outcome) => search_outcome_term(env, outcome),
        Err(e) => err(env, e),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_keytrans_verify_monitor<'a>(
    env: Env<'a>,
    suite_id: u16,
    context: &str,
    vrf_public_b64: &str,
    root_b64: &str,
    label_b64: &str,
    proof_b64: &str,
) -> Term<'a> {
    let verifier = match keytrans_verifier(env, suite_id, context, vrf_public_b64) {
        Ok(v) => v,
        Err(t) => return t,
    };
    let root = decode!(env, root_b64);
    let label = decode!(env, label_b64);
    let proof = decode!(env, proof_b64);
    match verifier.verify_monitor_bytes(&root, &label, &proof) {
        Ok(verified) => ok_val(env, verified),
        Err(e) => err(env, e),
    }
}

// ─── Ingestion Primitives (Slice 7) ──────────────────────────────────────────
//
// Deterministic, side-effect-free helpers for an Elixir operator pipeline.
// Sequencing state and tile I/O stay on the BEAM side (idiomatic); the NIF
// supplies the dedup digests, flush geometry, and Merkle recomputation over
// tile bytes the caller has already read.

#[rustler::nif]
fn nif_dedup_key_from_record<'a>(env: Env<'a>, namespace: &str, payload_b64: &str) -> Term<'a> {
    let ns = match Namespace::parse(namespace) {
        Ok(n) => n,
        Err(e) => return err(env, e),
    };
    let payload = decode!(env, payload_b64);
    let key = DedupKey::from_record(&ns, &payload);
    ok_val(env, b64::encode(key.as_bytes()))
}

#[rustler::nif]
fn nif_dedup_key_from_token<'a>(env: Env<'a>, namespace: &str, token_b64: &str) -> Term<'a> {
    let ns = match Namespace::parse(namespace) {
        Ok(n) => n,
        Err(e) => return err(env, e),
    };
    let token = decode!(env, token_b64);
    let key = DedupKey::from_token(&ns, &token);
    ok_val(env, b64::encode(key.as_bytes()))
}

#[rustler::nif]
fn nif_tiles_to_flush<'a>(env: Env<'a>, old_size: u64, new_size: u64) -> Term<'a> {
    match ingest::tiles_to_flush(old_size, new_size) {
        Ok(tiles) => ok_val(env, tile_paths(&tiles)),
        Err(e) => err(env, e),
    }
}

#[rustler::nif]
fn nif_entry_bundles_to_flush<'a>(env: Env<'a>, old_size: u64, new_size: u64) -> Term<'a> {
    match ingest::entry_bundles_to_flush(old_size, new_size) {
        Ok(tiles) => ok_val(env, entry_bundle_paths(&tiles)),
        Err(e) => err(env, e),
    }
}

fn tile_paths(tiles: &[Tile]) -> Vec<String> {
    tiles.iter().map(|t| t.path()).collect()
}

fn entry_bundle_paths(tiles: &[Tile]) -> Vec<String> {
    tiles.iter().map(|t| t.entries_path()).collect()
}

#[rustler::nif]
fn nif_tiles_for_size(env: Env<'_>, size: u64) -> Term<'_> {
    tile_paths(&tile::tiles_for_size(size)).encode(env)
}

#[rustler::nif]
fn nif_partial_width(level: u8, size: u64) -> u16 {
    tile::partial_width(level, size)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_tile_hashes<'a>(
    env: Env<'a>,
    level: u8,
    index: u64,
    width: u16,
    bytes_b64: &str,
) -> Term<'a> {
    let tile = match Tile::new(level, index, width) {
        Ok(t) => t,
        Err(e) => return err(env, e),
    };
    let bytes = decode!(env, bytes_b64);
    match tile.hashes(&bytes) {
        Ok(hashes) => ok_val(env, encode_hashes(&hashes)),
        Err(e) => err(env, e),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_recompute_root<'a>(env: Env<'a>, leaf_hashes_b64: Vec<String>) -> Term<'a> {
    let hashes = match decode_hashes(env, &leaf_hashes_b64) {
        Ok(h) => h,
        Err(t) => return t,
    };
    ok_val(env, b64::encode(&tile::recompute_root(&hashes)))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn nif_parent_hash<'a>(env: Env<'a>, tile_hashes_b64: Vec<String>) -> Term<'a> {
    let hashes = match decode_hashes(env, &tile_hashes_b64) {
        Ok(h) => h,
        Err(t) => return t,
    };
    match tile::parent_hash(&hashes) {
        Ok(hash) => ok_val(env, b64::encode(&hash)),
        Err(e) => err(env, e),
    }
}

fn encode_hashes(hashes: &[[u8; 32]]) -> Vec<String> {
    hashes.iter().map(|h| b64::encode(h)).collect()
}

fn decode_hashes<'a>(env: Env<'a>, hashes_b64: &[String]) -> Result<Vec<[u8; 32]>, Term<'a>> {
    hashes_b64
        .iter()
        .map(|h| {
            let bytes = b64::decode(h).map_err(|e| err(env, e))?;
            <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| err(env, format!("hash must be 32 bytes, got {}", bytes.len())))
        })
        .collect()
}

// ─── Anchoring (Slice 8) ──────────────────────────────────────────────────────
//
// Backend-agnostic anchoring / attestation: the *format* and the *verification*
// of committing a checkpoint head to an external, hard-to-equivocate medium
// (chain, notary, WORM storage, another log). The crate is deliberately I/O-free
// and so is this layer — the medium client, cadence, fees, and confirmation
// depth are the operator's (mosskeys') job. The `CommitmentSink` trait and its
// logic-only bridges are *not* wrapped: a trait with an associated error and a
// backend belongs on the BEAM side. Instead the operator publishes/fetches the
// commitment bytes itself, then compares them to `anchor_commitment/1`.

fn anchor_commitment_from_str(s: &str) -> Option<AnchorCommitment> {
    match s {
        "sha3_512" => Some(AnchorCommitment::Sha3_512),
        _ => None,
    }
}

fn anchor_commitment_str(alg: AnchorCommitment) -> &'static str {
    match alg {
        AnchorCommitment::Sha3_512 => "sha3_512",
        // `AnchorCommitment` is `#[non_exhaustive]`; a future menu entry surfaces
        // here as "unknown" until this NIF is updated to name it.
        _ => "unknown",
    }
}

/// Build the canonical bytes of an anchor attestation record from an explicit
/// checkpoint head. `commitment_alg` is a safe-menu tag string (`"sha3_512"`),
/// `medium` a printable-ASCII identifier (e.g. `"ethereum/mainnet"`), `locator`
/// the opaque external-commitment handle. Returns `{:ok, record_b64}`.
#[rustler::nif]
fn nif_anchor_record_canonical_bytes<'a>(
    env: Env<'a>,
    origin: &str,
    size: u64,
    root_b64: &str,
    commitment_alg: &str,
    medium: &str,
    locator_b64: &str,
) -> Term<'a> {
    let alg = match anchor_commitment_from_str(commitment_alg) {
        Some(a) => a,
        None => {
            return err(
                env,
                format!("unknown anchor commitment algorithm: {commitment_alg}"),
            );
        }
    };
    let root = decode_array!(env, root_b64, 32, "anchor root_hash");
    let medium = match Medium::parse(medium) {
        Ok(m) => m,
        Err(e) => return err(env, e),
    };
    let locator = decode!(env, locator_b64);
    match AnchorRecord::new(origin, size, root, alg, medium, locator) {
        Ok(rec) => ok_val(env, b64::encode(&rec.canonical_bytes())),
        Err(e) => err(env, e),
    }
}

/// `{origin, size, root_b64, commitment_alg, medium, locator_b64}`
fn anchor_record_tuple<'a>(env: Env<'a>, rec: &AnchorRecord) -> Term<'a> {
    (
        rec.origin().to_string(),
        rec.size(),
        b64::encode(rec.root_hash()),
        anchor_commitment_str(rec.commitment_alg()),
        rec.medium().as_str().to_string(),
        b64::encode(rec.locator()),
    )
        .encode(env)
}

/// Parse a canonical anchor record, returning its fields. Validates the layout,
/// format version, algorithm tag, medium grammar, and non-empty origin/locator.
#[rustler::nif]
fn nif_anchor_record_parse<'a>(env: Env<'a>, record_b64: &str) -> Term<'a> {
    let bytes = decode!(env, record_b64);
    match AnchorRecord::parse(&bytes) {
        Ok(rec) => ok_val(env, anchor_record_tuple(env, &rec)),
        Err(e) => err(env, e),
    }
}

/// The fixed-size commitment over the record's checkpoint head — the value an
/// operator publishes to (and re-fetches from) the external medium. Medium- and
/// locator-independent: the same head yields the same commitment. Returns
/// `{:ok, commitment_b64}`.
#[rustler::nif(schedule = "DirtyCpu")]
fn nif_anchor_commitment<'a>(env: Env<'a>, record_b64: &str) -> Term<'a> {
    let bytes = decode!(env, record_b64);
    match AnchorRecord::parse(&bytes) {
        Ok(rec) => ok_val(env, b64::encode(&rec.anchor_commitment())),
        Err(e) => err(env, e),
    }
}

/// The RFC 6962 Merkle leaf hash of the record's canonical bytes, so an operator
/// may also log its attestations as Layer-0 leaves. Returns `{:ok, hash_b64}`.
#[rustler::nif(schedule = "DirtyCpu")]
fn nif_anchor_record_rfc6962_leaf_hash<'a>(env: Env<'a>, record_b64: &str) -> Term<'a> {
    let bytes = decode!(env, record_b64);
    match AnchorRecord::parse(&bytes) {
        Ok(rec) => ok_val(env, b64::encode(&rec.rfc6962_leaf_hash())),
        Err(e) => err(env, e),
    }
}

/// Verify an anchored checkpoint: that the attestation binds the checkpoint
/// (verified from `note_text` + trusted `vkeys`), and — when `prev_note` is a
/// previously-anchored checkpoint note — that the newer checkpoint is an
/// append-only extension of it via the supplied RFC 9162 `consistency_proof`.
///
/// Pass `prev_note = nil` (and an empty proof) for the binding-only check.
#[rustler::nif(schedule = "DirtyCpu")]
fn nif_verify_anchored<'a>(
    env: Env<'a>,
    note_text: &str,
    vkeys: Vec<String>,
    record_b64: &str,
    prev_note: Option<String>,
    consistency_proof_b64: Vec<String>,
) -> Term<'a> {
    let trusted = match parse_vkeys(env, &vkeys) {
        Ok(t) => t,
        Err(t) => return t,
    };
    let cp = match Checkpoint::from_signed_note(note_text, &trusted) {
        Ok(cp) => cp,
        Err(e) => return err(env, e),
    };
    let bytes = decode!(env, record_b64);
    let record = match AnchorRecord::parse(&bytes) {
        Ok(r) => r,
        Err(e) => return err(env, e),
    };

    match prev_note {
        Some(prev) => {
            let prev_cp = match Checkpoint::from_signed_note(&prev, &trusted) {
                Ok(cp) => cp,
                Err(e) => return err(env, e),
            };
            let proof = match decode_proof(env, &consistency_proof_b64) {
                Ok(p) => p,
                Err(t) => return t,
            };
            let link = AnchorLink::new(&prev_cp, &proof);
            match anchor::verify_anchored(&cp, &record, Some(&link)) {
                Ok(()) => ok(env),
                Err(e) => err(env, e),
            }
        }
        None => match anchor::verify_anchored(&cp, &record, None) {
            Ok(()) => ok(env),
            Err(e) => err(env, e),
        },
    }
}

// ─── NIF Registration ────────────────────────────────────────────────────────
rustler::init!("Elixir.MetamorphicLog.Native");
