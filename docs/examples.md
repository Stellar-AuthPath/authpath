# Deterministic CLI examples

These commands use synthetic, valid Stellar strkeys and caller-provided
provenance. They do not identify real ledger accounts.

Run them from the repository root:

```sh
cargo run -p authpath-cli -- inspect examples/account-snapshot.json
cargo run -p authpath-cli -- --format json analyze examples/rotation-plan.json \
  --output /tmp/authpath-report.json
cargo run -p authpath-cli -- explain /tmp/authpath-report.json
cargo run -p authpath-cli -- verify \
  --report /tmp/authpath-report.json \
  --observed examples/observed-configuration.json
```

To see non-success classifications without network access:

```sh
cargo run -p authpath-cli -- analyze examples/blocked-rotation-plan.json
cargo run -p authpath-cli -- analyze examples/lockout-risk-rotation-plan.json
```

The first command exits with `10` and reports `BLOCKED`. The second exits with
`10` and reports an applied `LOCKOUT_RISK`; it is still a conditional model,
not a claim that a transaction was accepted.

The plan is a conditional model. The observed file's signer availability is
intentionally different to show that availability metadata is not treated as
an on-chain configuration field. The final comparison is still only an
offline configuration comparison.
