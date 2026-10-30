# Initial architecture

## Status and source audit

Phase C1 established the repository foundation and account configuration
model. Phase C2 adds a conservative authorization-threshold analysis engine
for classic Stellar transactions.

The checkout and the public `Stellar-AuthPath/authpath` repository were empty
at initialization. No approved AuthPath architecture document or
protocol-semantics specification was available in them, in the public
organization repositories, or in the local workspace. C2 therefore uses only
the authoritative Stellar protocol and stellar-core references listed below;
it does not claim to have reviewed unavailable Phase B files.

The following external protocol and tooling references were checked while
choosing the narrow C1 types:

- [SEP-23: Strkeys](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md)
  defines canonical textual forms for Stellar account and signer identifiers.
- [Stellar Set Options API reference](https://developers.stellar.org/docs/data/apis/horizon/api-reference/resources/operations/object/set-options)
  documents the 0–255 threshold domain and signer/master-key weight behavior.
- [CAP-2: Transaction level signature verification](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0002.md)
  requires transaction-level signature checks before operation side effects.
- [stellar-core OperationFrame](https://github.com/stellar/stellar-core/blob/master/src/transactions/OperationFrame.cpp)
  defines operation-source lookup, the default medium threshold, and
  per-operation threshold checks.
- [stellar-core TransactionFrame](https://github.com/stellar/stellar-core/blob/master/src/transactions/TransactionFrame.cpp)
  checks the transaction source at the low threshold and evaluates each
  operation source independently.
- [stellar-core SetOptionsOpFrame](https://github.com/stellar/stellar-core/blob/master/src/transactions/SetOptionsOpFrame.cpp)
  classifies signer/master-weight/threshold changes as high threshold and
  other supported SetOptions variations as medium threshold.
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
authpath-analysis   C2 authorization sufficiency analysis
        |
authpath-stellar    Stellar ledger/network adapters (deferred)
        |
authpath-cli        user-facing commands (deferred)
```

authpath-model and authpath-analysis are present because both have
independently testable behavior. The remaining names are planned logical
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

## C2 authorization analysis

### Inputs and output

The analyzer accepts:

- a validated transaction description containing a transaction source and
  authorization-relevant operation descriptions;
- a deduplicated collection of validated account snapshots; and
- an explicitly declared set of Ed25519 public identities available to the
  caller.

It returns one finding for the transaction-source check and one finding for
each supported operation. Each finding identifies the account and subject,
threshold category, required configured weight, available configured weight,
whether the requirement is met, and a structured missing-weight explanation.
Successful reports also expose fixed evidence limitations.

An unmet threshold is a valid negative result. Missing snapshots, duplicate
snapshots, unsupported operations or signer kinds, malformed descriptions,
network mismatch, and missing network provenance return structured errors and
must be treated as inconclusive rather than safe.

### Supported operation types and thresholds

| Authorization subject | Supported type or variation | Threshold |
| --- | --- | --- |
| Transaction source | Every supported transaction | Low |
| Operation | Payment | Medium |
| Operation | BumpSequence | Low |
| Operation | AccountMerge | High |
| Operation | SetOptions with master weight, any threshold, or signer present | High |
| Operation | SetOptions with only flags, inflation destination, or home domain present | Medium |

Other Stellar operation types are rejected explicitly. C2 does not assign a
default threshold to an unsupported operation.

### Source-account behavior

An operation with no explicit source uses the transaction source. An operation
with an explicit source is checked against that account's own snapshot and
thresholds. Configured weights from different accounts are never combined.
The transaction source is always checked separately at its low threshold.

A threshold of zero does not waive signing: stellar-core compares the
accumulated weight to the threshold only after a signature matches a listed
signer, so at least one declared identity with positive configured weight is
required for every check (`NoMatchingSigner` otherwise).

The master key contributes only when its Ed25519 identity is explicitly in the
available set. An additional signer contributes only when it is both
explicitly marked available in its snapshot and present in the caller's
available set. Zero weights contribute zero. Repeated available identities
are deduplicated.

The analyzer reuses the input snapshots for every operation. It does not
apply a SetOptions change while analyzing a later operation in the same
transaction; CAP-2 requires signature checks before operation side effects.
State changes visible to later transactions are outside C2 and belong to the
future rotation/simulation work.

### Safety meanings and limitations

MeetsConfiguredRequirements means only that the declared identities reach the
configured threshold values in the supplied snapshots. It does not mean that
signature bytes are valid, that a caller possesses any private key, that the
snapshots came from verified ledger evidence, or that the transaction will
execute successfully.

C2 does not model balances, reserves, sequence numbers, fees, preconditions,
asset validity, operation effects, transaction serialization, cryptographic
signatures, live network state, or post-transaction account configuration.

## Explicit non-goals

C2 does not implement the multi-transaction rotation planner, CLI,
ledger/network adapters, private-key storage, transaction signing or
submission, or any hosted service. The full authorization engine remains
incomplete.
