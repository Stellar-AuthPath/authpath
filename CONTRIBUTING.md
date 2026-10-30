# Contributing to Stellar AuthPath

AuthPath is an incomplete, phased project. Contributions must stay within the
current phase and must not imply that the authorization engine is complete.

## Before making a change

- Read the [architecture notes](docs/architecture.md) and the relevant phase
  request.
- Do not use real account secrets, private keys, or public-ledger evidence in
  tests or examples. Use deterministic fixtures.
- Keep dependencies and abstractions narrowly tied to an implemented
  behavior.

## Local checks

The repository uses Rust 1.99.1 for development and declares Rust 1.87 as its
minimum supported version. Before opening a pull request, run:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

Review dependencies with `cargo audit --deny warnings`. This checks the
locked dependency graph against the RustSec advisory database and includes
yanked-crate checks unless `--no-yanked` is explicitly supplied. At the
2026-10-30 review, cargo-audit 0.22.2 fetched the advisory database and
reported zero vulnerabilities or warnings across 23 locked dependencies; no
advisory or yanked-crate check was unavailable.

## Git and pull requests

Use a feature branch for changes after the initial repository branch and open
a pull request against `main`. Keep commits small and logically meaningful;
inspect the diff before staging and stage only intended files. Do not add AI
co-author trailers. Do not merge an unreviewed contributor pull request.

Pull requests should explain the behavior changed, the validation boundary,
the tests run, and any unresolved specification question. Changes that would
enable transaction signing, submission, key custody, deployment, or real
authorization decisions require an approved later-phase specification.
