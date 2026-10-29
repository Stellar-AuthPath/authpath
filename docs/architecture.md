# Initial architecture

## Status and source audit

Phase C1 implements only the repository foundation and the account
configuration model described in the Phase C1 development request.

The checkout and the public `Stellar-AuthPath/authpath` repository were empty
at initialization. No approved AuthPath architecture document or
protocol-semantics specification was available in them, in the public
organization repositories, or in the local workspace. Consequently, this
document records the explicit C1 boundary rather than inventing a larger
protocol contract. The missing approved specifications are an input required
before C2 behavior is designed.

The following external protocol and tooling references were checked while
choosing the narrow C1 types:

- [SEP-23: Strkeys](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md)
  defines canonical textual forms for Stellar account and signer identifiers.
- [Stellar Set Options API reference](https://developers.stellar.org/docs/data/apis/horizon/api-reference/resources/operations/object/set-options)
  documents the 0–255 threshold domain and signer/master-key weight behavior.
- [Rust 1.99.1 release list](https://blog.rust-lang.org/releases/) records the
  current stable release checked on 2026-10-29.
- [`stellar-strkey` 1.0.0](https://crates.io/crates/stellar-strkey/1.0.0)
  is the official Rust strkey crate selected for canonical parsing. Its
  upstream documentation currently describes the crate as early,
  incomplete, and not recommended for use, so it is intentionally isolated
  in `authpath-model` and is not used to make authorization decisions.

## Planned crate boundaries

```text
authpath-model      validated, provenance-bearing account data
        |
authpath-analysis   authorization analysis (deferred)
        |
authpath-stellar    Stellar ledger/network adapters (deferred)
        |
authpath-cli        user-facing commands (deferred)
```

Only `authpath-model` is present in C1. The other names are planned logical
boundaries, not empty APIs.

## C1 model boundary

An account configuration snapshot contains:

- a canonical Stellar account identity;
- a master-key weight in the protocol’s one-byte weight domain;
- low, medium, and high thresholds in that same domain;
- zero or more Ed25519 signer configurations;
- an explicit availability declaration for every configured signer; and
- provenance identifying how the snapshot was obtained and, when known, the
  Stellar network identity.

Availability is metadata supplied by the caller. It does not contain private
key material, and it is never inferred from a configured weight. An
`Unavailable` declaration is therefore different from a zero configured
weight.

The model accepts zero-weight signer entries because C1 explicitly requires
that snapshot boundary to be representable and testable. It does not model
the Set Options operation or claim that a zero-weight entry is a valid
operation request. Raw signer weights outside 0–255 are rejected, even though
the underlying Stellar XDR field is wider, because the account weight domain
being modeled is one byte.

Unsupported Stellar signer kinds are rejected at the conversion boundary.
Only Ed25519 signer keys are represented by the C1 model. Pre-authorized
transaction, hash-X, signed-payload, and future signer kinds are not silently
coerced into Ed25519 keys.

## Provenance and network identity

The snapshot provenance records whether data was supplied directly or read
from a ledger-backed source, together with an optional network identity and
optional ledger sequence. C1 does not fetch or verify public ledger evidence;
callers must provide provenance explicitly. The model rejects ledger-backed
provenance without a network identity or ledger sequence, and rejects a
network identity with an empty network passphrase.

## Explicit non-goals

C1 does not implement signature verification, threshold evaluation for a
transaction, transaction parsing, ledger/network access, private-key storage,
transaction signing or submission, a CLI, or any hosted service.
