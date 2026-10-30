# AuthPath documentation

This directory is the documentation entry point for Stellar AuthPath.

- [CLI reference](cli.md) — installation, commands, versioned JSON contracts,
  output formats, exit codes, examples, and limitations.
- [Initial architecture](architecture.md) — Phase C1–C4 scope, crate
  boundaries, validation rules, threshold classifications, and security
  boundaries.

The project remains intentionally narrow. The CLI describes caller-supplied
configuration and conditional models; it does not claim cryptographic
authorization, private-key possession, successful transaction execution, or
independently verified ledger evidence.
