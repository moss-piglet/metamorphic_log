# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this package, **do not open a public issue**.

Please report it privately via one of:

- **GitHub Security Advisories**: [Report a vulnerability](https://github.com/moss-piglet/metamorphic_log/security/advisories/new)
- **Email**: security@mosspiglet.dev

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Scope

This policy covers the `metamorphic_log` Hex package, including:

- The Elixir API (`MetamorphicLog.*`)
- The Rust NIF (`native/metamorphic_log_nif`) and its bindings
- Precompiled NIF distribution and checksum verification

The underlying transparency-log engine lives in the
[`metamorphic-log`](https://github.com/moss-piglet/metamorphic-log) Rust crate,
and the cryptographic primitives in
[`metamorphic-crypto`](https://github.com/moss-piglet/metamorphic-crypto);
vulnerabilities in those should be reported in their respective repositories.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Security Design

- All logic delegated to the audited `metamorphic-log` engine and the
  `metamorphic-crypto` core; the NIF layer is `#![forbid(unsafe_code)]` thin
  glue with no independent cryptography.
- Layer 1 is a fixed, witness-auditable RFC 6962 SHA-256 Merkle tree; signed
  notes/checkpoints follow C2SP. Additive hybrid post-quantum signatures
  (ML-DSA + Ed25519, strict-AND) and SHA3-512 CONIKS commitments wedge
  post-quantum integrity without changing the classical layer.
- Precompiled NIFs are distributed via GitHub Releases and verified at fetch
  time by `rustler_precompiled` against the committed `checksum-*.exs` (SHA-256).
- Release artifacts carry GitHub build-provenance attestations.
- CI gates every change on `cargo audit` (RustSec advisories), `clippy -D warnings`,
  and the full Elixir test suite across supported OTP/Elixir versions —
  including the cross-language byte-parity KAT.
