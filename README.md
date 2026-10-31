# Stellar AuthPath

[![CI](https://github.com/Stellar-AuthPath/authpath/actions/workflows/ci.yml/badge.svg)](https://github.com/Stellar-AuthPath/authpath/actions/workflows/ci.yml)
[![Rust 1.87+](https://img.shields.io/badge/Rust-1.87%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Stellar AuthPath is an offline Rust CLI for reviewing classic Stellar account authorization and signer/threshold rotation plans.**

[Read the documentation](https://stellar-authpath.github.io/authpath/) · [CLI reference](docs/cli.md) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## The problem

Stellar accounts can combine a master-key weight, additional signer weights,
and low, medium, and high authorization thresholds. A transaction that changes
those settings can be authorized now but leave a later transaction or the
account's own administration unreachable. The risk is especially easy to miss
when a plan adds, removes, or reweights signers across multiple transactions.

AuthPath makes those assumptions explicit before a transaction is submitted.
It uses Stellar's transaction-source and operation-source authorization rules,
threshold categories, signer weights, and ordered transaction semantics to
produce a conservative local analysis. It does not assert that a transaction
was signed or accepted by the network.

## What it does

The `authpath` binary reads versioned JSON from local files and provides four
commands:

- `inspect` validates and displays one account snapshot, including provenance
  and caller-declared signer availability.
- `analyze` runs the existing authorization and conditional rotation engines
  over an ordered rotation plan and writes a deterministic report.
- `explain` validates an untrusted report and presents its findings and
  limitations in human-readable or JSON form.
- `verify` performs an offline comparison between a modeled final
  configuration and an independently supplied observed snapshot.

The tool is intended for account operators, multisignature and treasury teams,
protocol engineers, and reviewers who need a reproducible pre-submission
check. It is not a wallet, signer, custody system, ledger explorer, or
transaction-submission service.

## Quick example

The repository includes synthetic, non-ledger examples. From the repository
root:

```sh
cargo run -p authpath-cli -- inspect examples/account-snapshot.json

cargo run -p authpath-cli -- --format json analyze \
  examples/rotation-plan.json --output /tmp/authpath-report.json

cargo run -p authpath-cli -- explain /tmp/authpath-report.json

cargo run -p authpath-cli -- verify \
  --report /tmp/authpath-report.json \
  --observed examples/observed-configuration.json
```

The example inputs use caller-provided provenance and synthetic valid strkeys.
They do not identify real accounts or make network calls. See the [CLI
reference](docs/cli.md) for output meanings and exit codes.

## Install and use locally

The development workspace requires Rust 1.87 or newer. The repository pins
Rust 1.99.1 for development and CI.

Run the binary from a checkout:

```sh
cargo run -p authpath-cli -- --help
```

Install it into the local Cargo bin directory:

```sh
cargo install --path crates/authpath-cli --locked
authpath --help
```

All inputs are bounded, strictly versioned, and rejected on malformed
identities, duplicate signers, contradictory declarations, unknown fields, or
unsupported schema versions. Output files use atomic installation; existing
files require explicit `--force` replacement.

## Supported boundary

AuthPath models classic Stellar account authorization with Ed25519 account and
signer identities. Rotation plans support `payment`, `bump_sequence`, and
authorization-relevant `set_options` changes for master weight, thresholds,
and signer weights. The model enforces the 20-signer limit, operation-source
authorization, pre-transaction authorization checks, and the plan-wide versus
account-state signer-availability contract.

The rotation boundary rejects AccountMerge and other unsupported operations.
Pre-authorized transaction, hash-X, and signed-payload signer types are not
silently converted to Ed25519; when they affect a conclusion, the result is
inconclusive. Balances, reserves, fees, sequence numbers, preconditions,
cryptographic signatures, concurrent ledger changes, and transaction
execution are not established by this tool.

## Read results accurately

AuthPath separates four claims:

1. **Configured authorization sufficiency** — declared identities meet the
   configured thresholds in supplied snapshots.
2. **Conditional rotation modeling** — an ordered plan is modeled assuming its
   authorized transitions succeed; lockout and invalid-transition findings are
   preserved.
3. **Offline configuration comparison** — modeled fields are compared with an
   observed file while retaining that file's provenance.
4. **Independently verified ledger evidence** — not available in this project.

Configured signer weight and caller-declared availability are never proof of
private-key possession. `verified_on_chain` is always false. A matching
offline file cannot become cryptographic or on-chain verification.

## Evidence and compatibility

The merged C1–C5 implementation has 166 workspace tests. The complete locked
workspace checks have been run with Rust 1.87.0 and the pinned Rust 1.99.1
toolchain. The repository CI checks formatting, compilation, Clippy with
warnings denied, tests, and Rustdoc; `cargo audit --deny warnings` is also run
locally against the locked dependency graph.

The [C5 audit record](docs/c5-audit.md) contains the protocol references,
adversarial coverage, confirmed corrections, dependency result, and remaining
limitations. The [submission-readiness record](docs/submission-readiness.md)
separates verified evidence from open review items.

## Contributing and security

Use deterministic, non-secret fixtures and read [Contributing](CONTRIBUTING.md)
before opening a pull request. Never put private keys, seed phrases, signed
transactions, or real account secrets in issues, tests, or examples. See the
[Security policy](SECURITY.md) for the reporting process and current scope.

AuthPath is released under the [Apache License 2.0](LICENSE).
