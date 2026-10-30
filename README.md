# Stellar AuthPath

[Documentation and CLI reference](docs/README.md)

Stellar AuthPath is a phased Rust project for conservative, offline analysis
of Stellar account authorization configuration. The current C4 deliverable
adds a local `authpath` CLI over the validated C1 model, C2 authorization
engine, and C3 conditional rotation engine.

## Current status

Phase C1 established the repository foundation and typed account snapshots.
Phase C2 provides conservative authorization sufficiency analysis for a
narrow set of classic Stellar operations. Phase C3 models ordered signer and
threshold rotations conditionally, including explicit signer-availability
contracts and dependent-step halting. Phase C4 provides local JSON input,
human-readable output, deterministic JSON reports, explanations, and offline
configuration comparison.

Phase C3 analyzes a proposed sequence of transactions that change signers,
signer weights, the master-key weight and thresholds on classic accounts. For
each step it checks authorization against the configuration that exists
before the step, applies the step's authorization-relevant changes
*conditionally*, and reports whether the changed accounts remain
administrable by the intersection of the plan-wide identities and the
account-state signer-availability declarations. Positive-weight signer
additions and reweightings must declare availability consistently with that
plan-wide set; contradictions halt the sequence as `INCONCLUSIVE`. Results
classified `SUPPORTED_REACHABLE`, `INCONCLUSIVE`, `LOCKOUT_RISK`,
`INVALID_TRANSITION` or `BLOCKED`. Every result is a conditional model, never
a verified on-chain outcome, and no result means an account is safe.

The implementation is not a wallet, signer, ledger verifier, or transaction
submission system. It must not be used as proof of real authorization or to
protect real funds. Configured signer weight and caller-declared availability
are never treated as evidence that a corresponding private key is possessed.

## Workspace

The planned logical components are:

- `authpath-model` — validated account identities, signer configuration,
  thresholds, availability declarations, and snapshot provenance.
- `authpath-analysis` — conservative transaction and operation authorization
  threshold analysis for the supported C2 operation set, and the C3 `rotation`
  module for multi-transaction signer and threshold change plans.
- `authpath-stellar` — deferred until ledger/network adapters are specified.
- `authpath-cli` — the offline `authpath` binary, versioned JSON adapters,
  deterministic reports, explanations, and configuration comparison.

Only authpath-stellar remains deferred. The CLI never fetches from a network,
stores secrets, signs, or submits transactions.

## Quick CLI example

Build and run the local binary:

```text
cargo run -p authpath-cli -- inspect examples/account-snapshot.json
cargo run -p authpath-cli -- --format json analyze examples/rotation-plan.json \
  --output /tmp/authpath-report.json
cargo run -p authpath-cli -- explain /tmp/authpath-report.json
cargo run -p authpath-cli -- verify \
  --report /tmp/authpath-report.json \
  --observed examples/observed-configuration.json
```

See the [CLI reference](docs/cli.md) for schemas, exit codes, output policy,
limitations, and the distinction between configured sufficiency, conditional
rotation modeling, offline comparison, and genuine independently verified
ledger evidence (which is not available in this phase).

## Development

The repository pins its development toolchain to Rust 1.99.1 and declares Rust
1.87 as its minimum supported version. Run the following checks from the
repository root:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo audit --deny warnings
```

See [Contributing](CONTRIBUTING.md) for the contribution workflow and
[Security](SECURITY.md) for the project’s current safety boundaries.
