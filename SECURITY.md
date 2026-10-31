# Security policy

Stellar AuthPath is an offline analysis tool for a documented subset of
classic Stellar account authorization and signer rotation. It is not safe to
use as the sole basis for production financial decisions. It does not sign or
submit transactions, prove private-key possession, establish authoritative
ledger state, or guarantee that modeled transactions will execute. It does
not model reserves, fees, sequence numbers, or transaction execution.
Unsupported classic operations and Soroban authorization behavior remain
outside its scope.

## Reporting a vulnerability

Please do not include private keys, seed phrases, signed transactions, or
other secrets in an issue or pull request. If GitHub private vulnerability
reporting is enabled for this repository, use the repository’s **Security →
Report a vulnerability** flow. Otherwise, contact the maintainers privately
through the Stellar-AuthPath GitHub organization and do not publish exploit
details until a private channel is available.

Reports should include the affected commit, a minimal reproduction that uses
deterministic test data, impact, and any proposed mitigation. Do not probe
public Stellar networks or submit transactions as part of a report.

## Scope

The current security boundary is the Rust model and analysis crates, their
validation logic, deterministic test fixtures, and the CLI's untrusted local
JSON boundary. The analysis result means only that caller-declared Ed25519
identities reach configured threshold values in supplied snapshots; it is not
cryptographic authorization proof. A rotation classification is a
conditional statement about supplied snapshots and declared signer
availability, not an on-chain result. The project has no deployed service,
database, key custody, network/ledger integration, or transaction-submission
surface. This policy must be revised if later changes introduce those
surfaces.
