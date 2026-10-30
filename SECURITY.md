# Security policy

Stellar AuthPath is incomplete and is not safe for real authorization
decisions, real funds, private keys, or production deployment. Phase C2 adds
configured-threshold analysis for a narrow operation set, Phase C3 adds a
conditional model of multi-transaction signer and threshold changes, and C4
adds an offline CLI over those APIs. None verifies signatures, proves
private-key possession, fetches or verifies ledger evidence, models reserves,
fees or sequence numbers, simulates execution, or signs transactions. A
rotation result or offline comparison is a model under caller declarations,
never a guarantee that a sequence is safe to submit.

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
surface. This policy will be revised before any later phase introduces those
surfaces.
