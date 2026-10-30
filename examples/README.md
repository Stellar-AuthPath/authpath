# Deterministic CLI examples

These files use synthetic, valid Stellar strkeys and caller-provided
provenance. They do not identify real ledger accounts.

```sh
cargo run -p authpath-cli -- inspect examples/account-snapshot.json
cargo run -p authpath-cli -- --format json analyze examples/rotation-plan.json \
  --output /tmp/authpath-report.json
cargo run -p authpath-cli -- explain /tmp/authpath-report.json
cargo run -p authpath-cli -- verify \
  --report /tmp/authpath-report.json \
  --observed examples/observed-configuration.json
```

The plan is a conditional model. The observed file's signer availability is
intentionally different to show that availability metadata is not treated as
an on-chain configuration field. The final comparison is still only an
offline configuration comparison.
