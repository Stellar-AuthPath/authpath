# Initial architecture

## Status and source audit

Phase C1 established the repository foundation and account configuration
model. Phase C2 adds a conservative authorization-threshold analysis engine
for classic Stellar transactions. Phase C3 adds a conditional rotation safety
engine over sequences of such transactions. Phase C4 adds a local CLI and
versioned JSON reporting boundary over those validated APIs.

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
- [stellar-core SignatureChecker](https://github.com/stellar/stellar-core/blob/master/src/transactions/SignatureChecker.cpp)
  accumulates signer weight and compares it with the needed weight only after
  a signature matches a listed signer. C3 relied on this to correct C2's
  handling of a zero threshold.
- [stellar-xdr](https://github.com/stellar/stellar-xdr) fixes `MAX_SIGNERS`
  at 20 and `MAX_OPS_PER_TX` at 100.
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
authpath-cli        offline user-facing commands and reports
```

authpath-model, authpath-analysis, and authpath-cli have independently
testable behavior. authpath-stellar remains a planned logical boundary, not
an empty API.

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
State changes visible to later transactions are outside C2 and are handled by
the C3 rotation engine below.

### Safety meanings and limitations

MeetsConfiguredRequirements means only that the declared identities reach the
configured threshold values in the supplied snapshots. It does not mean that
signature bytes are valid, that a caller possesses any private key, that the
snapshots came from verified ledger evidence, or that the transaction will
execute successfully.

C2 does not model balances, reserves, sequence numbers, fees, preconditions,
asset validity, operation effects, transaction serialization, cryptographic
signatures, live network state, or post-transaction account configuration.

## C3 rotation safety engine

C3 lives in the `rotation` module of `authpath-analysis` and reuses the C1
model and the C2 `analyze` function unchanged.

### C2 correction made in C3

C2 reported a requirement as met when available weight equalled a threshold of
zero, including when no signer was available. stellar-core compares weight
with the needed weight only after a signature matches a listed signer, and the
master key is listed only while its weight is non-zero. A threshold of zero
therefore still needs one matching signer of positive weight. C2 now reports
`NoMatchingSigner` in that case.

### Plan representation

A `RotationPlan` holds the initial validated snapshots, the declared
available signer identities, and an ordered list of `PlannedTransaction`s.
Each planned transaction carries a C2 `TransactionDescription`, an explicit
post-operation availability declaration for every positive-weight signer
change, an optional reserve declaration, and optional caller-supplied expected
resulting configurations. These expectations are assertions about the
intended result, not proof that a ledger executed the transaction.

The plan-wide Ed25519 identity set is the caller's explicit declaration of
identities available throughout the sequence. A configured signer contributes
to reachability only when its account-state availability declaration is also
`Available`; reachability uses this intersection and never infers possession
from weight or a public key. For a positive-weight addition or reweight,
`Available` must be present in the plan-wide set and `Unavailable` must be
absent. A contradiction is `INCONCLUSIVE`, not an implicit possession claim.

Rejected at construction: empty plans and plans over 256 transactions (an
AuthPath resource bound, not a protocol limit); more than 100 operations per
transaction (protocol limit); AccountMerge and any unknown operation; empty
SetOptions; a signer equal to its own operation source; missing, duplicate or
mismatched availability declarations; and expected configurations that list
more than 20 signers, zero-weight signers, duplicates, or the master key.

Declared signer kinds the model cannot evaluate (pre-authorized transaction,
hash-X, signed payload) are retained rather than coerced and make unmet
requirements `INCONCLUSIVE`. No availability declaration proves possession of
any private key.

### Supported and unsupported transitions

| Operation | Treatment |
| --- | --- |
| SetOptions: master-key weight | Applied |
| SetOptions: low, medium, high thresholds | Applied |
| SetOptions: signer add, re-weight, remove (weight 0) | Applied; 20-signer limit enforced; removing an absent signer is a no-op |
| SetOptions: flags, inflation destination, home domain | Accepted, no authorization effect modeled |
| Payment, BumpSequence | Authorized; no authorization-state effect |
| AccountMerge and all other operations | Rejected at plan construction |

Operations in one transaction apply in order, and the transaction is atomic.
Each operation applies to its own source account, so a plan may change several
accounts and use a transaction source different from an operation source.

### Step semantics

For each transaction, in order:

1. C2 authorizes the transaction source at its low threshold and each
   operation source at the operation's threshold, against the state *before*
   the transaction. All operations use the pre-transaction state, matching
   stellar-core's up-front signature checks.
2. If authorization is met, availability declarations are checked against the
   plan-wide identity set. A contradiction is `INCONCLUSIVE` and halts
   dependent analysis.
3. The changes are applied conditionally, assuming the transaction succeeds.
4. Any caller-supplied expected configuration is compared with the modeled
   result. A mismatch is `INCONCLUSIVE`; the candidate result is not accepted
   into the sequential model because the expectation is an assertion, not
   ledger evidence.
5. Each account whose configuration changed is checked for administrative
   reach (below).
6. Only a result with no availability or expectation mismatch becomes the
   starting state of the next transaction.

The first step that is unauthorized, invalid, lacks evidence, or has an
availability or expectation mismatch halts the chain. Later steps are
reported `INCONCLUSIVE` with `PredecessorNotApplied` rather than being
evaluated against a state that was never authoritatively accepted by the
model.

### Administrative reach and lockout

Reachability compares weight, not signer counts. For each threshold, the
declared-available weight is compared with the threshold (and a matching
positive-weight signer is required). A threshold is:

- `Reachable` when declared-available signers meet it;
- `RequiresUnavailableSigners` when they do not, but the account's full
  configured weight, including signers declared unavailable, would; or
- `Unreachable` when no configured signer set can meet it.

A changed account that loses high-threshold reach is a `LOCKOUT_RISK`, with
the kind recorded. Loss of low-threshold reach while high remains is also
reported, because the account could then administer itself only through a
different transaction source. A single sufficient signer is not a lockout.
`Unreachable` is permanent only if the snapshot is complete; the model cannot
see signer kinds C1 does not represent.

### Classifications

| Classification | Meaning |
| --- | --- |
| `SUPPORTED_REACHABLE` | Under the declared assumptions the step is authorized and every changed account stays administrable. |
| `INCONCLUSIVE` | Missing or unsupported evidence, contradictory declarations, an expectation that disagrees with the model, or an unevaluated predecessor. |
| `LOCKOUT_RISK` | The step is authorized but a changed account can no longer be administered by the declared signers. |
| `INVALID_TRANSITION` | The change exceeds the signer limit or contradicts a declared reserve shortfall. |
| `BLOCKED` | A supported authorization requirement is not met by the declared signers. |

The plan classification is the most severe step classification. No category
means an account is safe. `SUPPORTED_REACHABLE` is a statement about the model.

### What a result is not

Every report is labeled `ConditionalModel`, `verified_on_chain()` is always
`false`, and the following are never established: signature validity,
private-key possession, snapshot accuracy against a ledger, reserves and
balances (`SET_OPTIONS_LOW_RESERVE`, subentry and sponsorship limits),
sequence numbers, fees, preconditions, ledger acceptance and ordering,
concurrent changes by other parties between planned transactions, or any
effect other than authorization configuration. A caller may declare a reserve
shortfall, which is treated as given; the engine never derives one.
Derived configurations are marked as modeled and are never ledger-backed.

## C4 offline CLI boundary

The `authpath` binary accepts four local commands: `inspect` validates and
displays one account snapshot, `analyze` invokes the C3 rotation engine,
`explain` validates and explains a generated analysis report, and `verify`
performs an offline comparison with an independently supplied observed
configuration. JSON contracts are versioned, strict about unknown fields, and
bounded before deserialization. The CLI reuses the existing model
constructors and analysis APIs; it does not reimplement authorization math.

Human output and JSON output carry the same conditional semantics. Analysis
reports identify their `conditional_model` basis and never claim on-chain
verification. Comparison reports identify their
`offline_configuration_comparison` basis and preserve the observed file's
provenance. An exact comparison is not cryptographic verification and is not
proof that a ledger executed a transaction.

Output files are written and synced in a same-directory temporary file. Without
`--force`, the CLI atomically creates the destination directory entry with a
hard link and rejects an existing or concurrently created destination; it does
not fall back to an existence check followed by rename. With `--force`, an
explicit replacement uses the platform's rename semantics. If no-replace hard
links are unsupported, the CLI returns an operational error and removes its
temporary file. Input files are read-only from the CLI's perspective. The CLI
has no key, wallet, network, database, hosted-service, or transaction-
submission surface.

## Explicit non-goals

C4 does not implement ledger/network adapters, private-key storage,
transaction signing or submission, wallet connections, or any hosted service.
Pre-authorized transaction, hash-X and signed-payload signers, AccountMerge,
fee-bump transactions, sponsorship and muxed accounts remain outside the
supported model. The full authorization engine remains incomplete.

## Verification

The repository CI runs formatting, workspace compilation, Clippy with denied
warnings, all workspace tests, and a workspace documentation build with
rustdoc warnings denied. The dependency audit command is:

```text
cargo audit --deny warnings
```

At the 2026-10-30 review, cargo-audit 0.22.2 fetched its RustSec advisory
database and found no vulnerabilities or warnings in the current locked
dependency graph. Its default yanked-crate check was available and passed; no
advisory or yanked-crate check was unavailable.
