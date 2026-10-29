# Security policy

Stellar AuthPath is incomplete and is not safe for real authorization
decisions, real funds, private keys, or production deployment. Phase C1 only
validates account-configuration data; it does not verify signatures or sign
transactions.

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

The current security boundary is the Rust model crate and its validation
logic. The project has no deployed service, database, key custody, or
transaction-submission surface. This policy will be revised before any later
phase introduces those surfaces.
