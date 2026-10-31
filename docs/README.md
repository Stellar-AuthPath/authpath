# Stellar AuthPath documentation

This directory is the source of truth for the current AuthPath MVP. It
describes implemented behavior and evidence, not a future wallet, hosted
service, or ledger integration.

- [Architecture](architecture.md) — components, data flow, trust boundaries,
  Stellar-specific rules, classifications, and non-goals.
- [CLI reference](cli.md) — installation, commands, versioned JSON contracts,
  output policy, exit codes, examples, and limitations.
- [C5 independent audit](c5-audit.md) — protocol references, confirmed
  findings, adversarial coverage, reproducibility evidence, and limitations.
- [Submission readiness](submission-readiness.md) — evidence, ecosystem
  positioning, governance status, readiness classifications, and blockers.
- [Deterministic examples](examples.md) — offline CLI commands and expected
  classifications using synthetic fixtures.

The examples use synthetic valid strkeys and caller-provided provenance; they
do not identify real accounts or prove ledger state.

## Documentation site status

The Markdown source is built as a small mdBook and published through the
repository's GitHub Pages workflow. The published documentation is available
at [stellar-authpath.github.io/authpath/](https://stellar-authpath.github.io/authpath/).
The source Markdown remains the repository's canonical documentation.

All documentation preserves the same boundary: configured authorization
sufficiency, conditional rotation modeling, and offline configuration
comparison are different from independently verified ledger evidence, which
is not available in this project.
