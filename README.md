# Stellar AuthPath

[Documentation](docs/README.md)

Stellar AuthPath is an incomplete Rust project for analyzing authorization
material associated with Stellar accounts. It is being developed in explicit
phases; the current work establishes the repository foundation for Phase C1.

## Current status

Phase C1 is limited to the repository foundation and a typed account
configuration model. It does not contain a CLI, authorization engine, ledger
reader, transaction signer, transaction submitter, database, or hosted
service.

The implementation is incomplete and must not be used to make real
authorization decisions or to protect real funds. Configured signer weight is
never treated as evidence that the corresponding private key is available.

## Workspace

The planned logical components are:

- `authpath-model` — validated account identities, signer configuration,
  thresholds, availability declarations, and snapshot provenance.
- `authpath-analysis` — deferred until analysis behavior is specified.
- `authpath-stellar` — deferred until ledger/network adapters are specified.
- `authpath-cli` — deferred until the command-line contract is specified.

Only `authpath-model` is created while it has meaningful, independently
testable behavior. The remaining components will not be added as empty
placeholders.

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
