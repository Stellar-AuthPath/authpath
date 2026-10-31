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

The repository also contains [deterministic examples](../examples/README.md).
They use synthetic valid strkeys and caller-provided provenance; they do not
identify real accounts or prove ledger state.

## Documentation site status

The Markdown source can be built as a small mdBook and the repository includes
a GitHub Pages workflow configuration. GitHub Pages is not currently enabled
for this repository, so no public documentation URL is claimed here. A
maintainer must set **Settings → Pages → Build and deployment → Source →
GitHub Actions** before the deployment job can publish the generated book.
After that setting is made, the maintainer should run the documentation
workflow and verify the resulting URL before adding a public-site link or
badge to the README.

All documentation preserves the same boundary: configured authorization
sufficiency, conditional rotation modeling, and offline configuration
comparison are different from independently verified ledger evidence, which
is not available in this project.
