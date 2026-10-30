# Stellar AuthPath

[Documentation](docs/README.md)

Stellar AuthPath is an incomplete Rust project for analyzing authorization
material associated with Stellar accounts. It is being developed in explicit
phases; the current work establishes the repository foundation for Phase C1.
The current implementation also contains the conservative authorization
analysis engine from Phase C2 and the conditional rotation safety engine from
Phase C3.

## Current status

Phase C1 established the repository foundation and a typed account
configuration model. Phase C2 now adds a conservative authorization analysis
engine for a narrow set of classic Stellar operations. It does not contain a
CLI, ledger reader, transaction signer, transaction submitter, database, or
hosted service.

Phase C3 analyzes a proposed sequence of transactions that change signers,
signer weights, the master-key weight and thresholds on classic accounts. For
each step it checks authorization against the configuration that exists
before the step, applies the step's authorization-relevant changes
*conditionally*, and reports whether the changed accounts remain
administrable by the signers the caller declared available. Results are
classified `SUPPORTED_REACHABLE`, `INCONCLUSIVE`, `LOCKOUT_RISK`,
`INVALID_TRANSITION` or `BLOCKED`. Every result is a conditional model, never
a verified on-chain outcome, and no result means an account is safe.

The implementation is incomplete and must not be used to make real
authorization decisions or to protect real funds. Configured signer weight is
never treated as evidence that the corresponding private key is available.

## Workspace

The planned logical components are:

- `authpath-model` — validated account identities, signer configuration,
  thresholds, availability declarations, and snapshot provenance.
- `authpath-analysis` — conservative transaction and operation authorization
  threshold analysis for the supported C2 operation set, and the C3 `rotation`
  module for multi-transaction signer and threshold change plans.
- `authpath-stellar` — deferred until ledger/network adapters are specified.
- `authpath-cli` — deferred until the command-line contract is specified.

Only authpath-stellar and authpath-cli remain deferred. They will not be added
as empty placeholders.

## Development

The repository pins its development toolchain to Rust 1.99.1 and declares Rust
1.87 as its minimum supported version. Run the following checks from the
repository root:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
```

See [Contributing](CONTRIBUTING.md) for the contribution workflow and
[Security](SECURITY.md) for the project’s current safety boundaries.
